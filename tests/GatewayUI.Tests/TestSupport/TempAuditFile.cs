using GatewayUI.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;

namespace GatewayUI.Tests.TestSupport;

/// <summary>
/// A throwaway directory holding one payment audit file, plus factories for
/// services that write to it. Disposing removes the directory.
/// </summary>
public sealed class TempAuditFile : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "gatewayui-tests-" + Guid.NewGuid().ToString("N"));

    public TempAuditFile() => Directory.CreateDirectory(_directory);

    public string Path_ => Path.Combine(_directory, "payment-webhooks.jsonl");

    public string[] ReadLines() =>
        File.Exists(Path_) ? File.ReadAllLines(Path_).Where(l => l.Length > 0).ToArray() : [];

    public IConfiguration Configuration(params (string Key, string Value)[] extra)
    {
        var values = new Dictionary<string, string?> { ["PaymentAuditPath"] = Path_ };
        foreach (var (key, value) in extra)
        {
            values[key] = value;
        }
        return new ConfigurationBuilder().AddInMemoryCollection(values).Build();
    }

    /// <summary>A new service instance over the same file, as after a process restart.</summary>
    public PaymentAuditService NewAuditService(StubHttpHandler? http = null) =>
        new(new FakeHostEnvironment(_directory), Configuration(), new StubHttpClientFactory(http ?? StubHttpHandler.Default()), NullLogger<PaymentAuditService>.Instance);

    public RazorpayPaymentService NewPaymentService(StubHttpHandler? http = null)
    {
        var handler = http ?? StubHttpHandler.Default();
        return new RazorpayPaymentService(
            new StubHttpClientFactory(handler),
            Configuration(),
            NewAuditService(handler),
            NullLogger<RazorpayPaymentService>.Instance);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
            // best-effort cleanup of a temp directory
        }
        catch (UnauthorizedAccessException)
        {
            // best-effort cleanup of a temp directory
        }
    }

    private sealed class FakeHostEnvironment(string contentRoot) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Testing";
        public string ApplicationName { get; set; } = "GatewayUI.Tests";
        public string ContentRootPath { get; set; } = contentRoot;
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
