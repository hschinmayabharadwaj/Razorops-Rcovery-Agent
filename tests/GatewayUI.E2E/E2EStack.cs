using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Playwright;

namespace GatewayUI.E2E;

/// <summary>
/// The whole system, for real: the Go stream-server (seeded with the canonical
/// batch), the Blazor app pointed at it, and a headless browser. Everything the
/// processes write goes to a temp directory; the repository is not touched.
/// </summary>
public sealed class E2EStack : IAsyncLifetime
{
    private const string AdminKey = "admin_key_demo";
    private static readonly TimeSpan StartupTimeout = TimeSpan.FromSeconds(90);

    private readonly string _tempDir = Path.Combine(Path.GetTempPath(), "gatewayui-e2e-" + Guid.NewGuid().ToString("N"));
    private readonly StringBuilder _goLog = new();
    private readonly StringBuilder _appLog = new();
    private Process? _goServer;
    private Process? _app;
    private IPlaywright? _playwright;

    public string AppUrl { get; private set; } = "";
    public string GoUrl { get; private set; } = "";
    public IBrowser Browser { get; private set; } = null!;

    public static bool Enabled => Environment.GetEnvironmentVariable(E2EFactAttribute.SwitchVariable) == "1";

    public async Task InitializeAsync()
    {
        if (!Enabled)
        {
            return;
        }
        Directory.CreateDirectory(_tempDir);
        var repoRoot = FindRepoRoot();

        await StartGoServerAsync(repoRoot);
        await StartAppAsync(repoRoot);

        _playwright = await Playwright.CreateAsync();
        Browser = await LaunchBrowserAsync(_playwright);
    }

    // Tries each candidate browser in turn and reports every failure if none
    // can be launched.
    private static async Task<IBrowser> LaunchBrowserAsync(IPlaywright playwright)
    {
        var failures = new List<string>();
        foreach (var channel in BrowserChannels())
        {
            try
            {
                return await playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions { Headless = true, Channel = channel });
            }
            catch (PlaywrightException ex)
            {
                failures.Add($"{channel ?? "chromium (Playwright build)"}: {ex.Message.Split('\n')[0]}");
            }
        }
        throw new InvalidOperationException(
            "No browser could be launched. Install Chrome or Edge, or run 'pwsh bin/Debug/net10.0/playwright.ps1 install chromium'.\n"
            + string.Join("\n", failures));
    }

    public async Task<IPage> NewPageAsync()
    {
        var page = await Browser.NewPageAsync(new BrowserNewPageOptions { BaseURL = AppUrl });
        page.SetDefaultTimeout(20_000);
        return page;
    }

    public async Task DisposeAsync()
    {
        if (Browser is not null)
        {
            await Browser.DisposeAsync();
        }
        _playwright?.Dispose();
        Stop(_app);
        Stop(_goServer);
        try
        {
            if (Directory.Exists(_tempDir))
            {
                Directory.Delete(_tempDir, recursive: true);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // best-effort cleanup of a temp directory
        }
    }

    // An installed Chrome/Edge needs no browser download, so those are tried
    // first; null is Playwright's own Chromium build. E2E_BROWSER_CHANNEL pins
    // one choice ("chrome", "msedge", or "chromium" for Playwright's build).
    private static IEnumerable<string?> BrowserChannels()
    {
        var configured = Environment.GetEnvironmentVariable("E2E_BROWSER_CHANNEL");
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return [configured == "chromium" ? null : configured];
        }
        return ["chrome", "msedge", null];
    }

    private async Task StartGoServerAsync(string repoRoot)
    {
        var goDir = Path.Combine(repoRoot, "go");
        var binary = Path.Combine(_tempDir, RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "stream-server.exe" : "stream-server");

        var build = Run("go", goDir, new Dictionary<string, string>(), _goLog, "build", "-o", binary, "./cmd/stream-server");
        await build.WaitForExitAsync();
        if (build.ExitCode != 0)
        {
            throw new InvalidOperationException("go build failed:\n" + _goLog);
        }

        var port = FreePort();
        GoUrl = $"http://127.0.0.1:{port}";
        _goServer = Run(binary, _tempDir, new Dictionary<string, string> { ["PORT"] = "" }, _goLog,
            "-port", port.ToString(),
            "-audit", Path.Combine(_tempDir, "audit.log.jsonl"),
            "-flows", Path.Combine(goDir, "data", "flows"),
            "-workdir", Path.Combine(_tempDir, "work"),
            "-seed");

        await WaitUntilUpAsync(_goServer, _goLog, "Go stream-server", async http =>
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, GoUrl + "/chain-status");
            request.Headers.Add("X-API-Key", AdminKey);
            using var response = await http.SendAsync(request);
            return response.StatusCode == HttpStatusCode.OK;
        });
    }

    private async Task StartAppAsync(string repoRoot)
    {
        var port = FreePort();
        AppUrl = $"http://127.0.0.1:{port}";
        var environment = new Dictionary<string, string>
        {
            ["ASPNETCORE_URLS"] = AppUrl,
            ["ASPNETCORE_ENVIRONMENT"] = "Development",
            ["GO_BACKEND_URL"] = GoUrl,
            ["PaymentAuditPath"] = Path.Combine(_tempDir, "payment-webhooks.jsonl"),
            ["RAZORPAY_KEY_ID"] = "rzp_test_e2e",
            ["RAZORPAY_KEY_SECRET"] = "e2e_key_secret",
            ["RAZORPAY_WEBHOOK_SECRET"] = "e2e_webhook_secret",
        };
        _app = Run("dotnet", repoRoot, environment, _appLog,
            "run", "--no-build", "--no-launch-profile", "--configuration", BuildConfiguration,
            "--project", Path.Combine("gateway-ui", "GatewayUI.csproj"));

        await WaitUntilUpAsync(_app, _appLog, "Blazor app", async http =>
        {
            using var response = await http.GetAsync(AppUrl + "/");
            return response.StatusCode == HttpStatusCode.OK;
        });
    }

#if DEBUG
    private const string BuildConfiguration = "Debug";
#else
    private const string BuildConfiguration = "Release";
#endif

    private static Process Run(string fileName, string workingDirectory, Dictionary<string, string> environment, StringBuilder log, params string[] arguments)
    {
        var info = new ProcessStartInfo(fileName)
        {
            WorkingDirectory = workingDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var argument in arguments)
        {
            info.ArgumentList.Add(argument);
        }
        foreach (var (key, value) in environment)
        {
            info.Environment[key] = value;
        }

        var process = new Process { StartInfo = info };
        void Capture(object _, DataReceivedEventArgs e)
        {
            if (e.Data is not null)
            {
                lock (log)
                {
                    log.AppendLine(e.Data);
                }
            }
        }
        process.OutputDataReceived += Capture;
        process.ErrorDataReceived += Capture;
        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        return process;
    }

    private static async Task WaitUntilUpAsync(Process process, StringBuilder log, string name, Func<HttpClient, Task<bool>> probe)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
        var deadline = DateTime.UtcNow + StartupTimeout;
        while (DateTime.UtcNow < deadline)
        {
            if (process.HasExited)
            {
                throw new InvalidOperationException($"{name} exited with code {process.ExitCode} during startup:\n{Snapshot(log)}");
            }
            try
            {
                if (await probe(http))
                {
                    return;
                }
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
            {
                // not listening yet
            }
            await Task.Delay(250);
        }
        throw new TimeoutException($"{name} did not become ready within {StartupTimeout.TotalSeconds:0}s:\n{Snapshot(log)}");
    }

    private static string Snapshot(StringBuilder log)
    {
        lock (log)
        {
            return log.ToString();
        }
    }

    private static void Stop(Process? process)
    {
        if (process is null)
        {
            return;
        }
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit(5000);
            }
        }
        catch (InvalidOperationException)
        {
            // already gone
        }
        finally
        {
            process.Dispose();
        }
    }

    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private static string FindRepoRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "RazorGateway.slnx")))
        {
            directory = directory.Parent;
        }
        return directory?.FullName ?? throw new InvalidOperationException("Could not locate the repository root (RazorGateway.slnx).");
    }
}
