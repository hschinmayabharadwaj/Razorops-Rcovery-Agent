using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using GatewayUI.Models;

namespace GatewayUI.Services;

// Result of a backend call. The UI renders these three states honestly rather
// than catching raw exceptions: data, a permission denial (401/403), or an
// error (network / 5xx / empty body).
public enum ApiStatus { Ok, Denied, Error }

public record BackendError(
    [property: JsonPropertyName("error")] string? Error,
    [property: JsonPropertyName("reason")] string? Reason,
    [property: JsonPropertyName("actor")] string? Actor,
    [property: JsonPropertyName("action")] string? Action
);

public record ApiResult<T>(ApiStatus Status, T? Data, BackendError? Denied, string? Error)
{
    public bool Ok => Status == ApiStatus.Ok;
    public bool AuthDenied => Status == ApiStatus.Denied;
    public bool Failed => Status == ApiStatus.Error;

    public static ApiResult<T> Success(T data) => new(ApiStatus.Ok, data, null, null);
    public static ApiResult<T> Unauthorized(BackendError? e) => new(ApiStatus.Denied, default, e, null);
    public static ApiResult<T> Failure(string message) => new(ApiStatus.Error, default, null, message);
}

public interface IGatewayApi
{
    string BaseUrl { get; }
    string CurrentRole { get; }
    string CurrentKey { get; }
    event Action? RoleChanged;
    void SetRole(string role);
    Task<ApiResult<MetricsDto>> GetMetricsAsync();
    Task<ApiResult<ExceptionsDto>> GetExceptionsAsync();
    Task<ApiResult<PolicyComparisonDto>> GetComparisonAsync();
    Task<ApiResult<PrescoreDto>> GetPrescoreAsync();
    Task<ApiResult<SandboxDto>> GetSandboxAsync(string? scenario = null);
    Task<ApiResult<ChainStatusDto>> GetChainStatusAsync();
    Task<ApiResult<string>> PostTamperAsync();
    Task<ApiResult<AdminActionResult>> PostAdminActionAsync(AdminActionRequest request);
    HttpRequestMessage NewRequest(HttpMethod method, string path);
}

// GatewayApiService is a singleton (Blazor Server host) that owns the active
// demo role/credential and issues typed requests to the Go adapter, attaching
// the deny-by-default X-API-Key header on every call. No business logic lives
// here — this is transport + honest error surfacing only.
public class GatewayApiService : IGatewayApi
{
    public static readonly string[] Roles = { "admin", "operator", "auditor" };
    // Demo credential for the Go adapter's admin role (see go/rz/auth.go).
    public const string AdminDemoKey = "admin_key_demo";

    private static readonly Dictionary<string, string> RoleKeys = new()
    {
        ["admin"] = AdminDemoKey,
        ["operator"] = "op_key_demo",
        ["auditor"] = "audit_key_demo",
    };

    private readonly IHttpClientFactory _factory;
    private string _role = "admin";

    public GatewayApiService(IHttpClientFactory factory)
    {
        _factory = factory;
    }

    public string BaseUrl => Environment.GetEnvironmentVariable("GO_BACKEND_URL") ?? "http://localhost:8090";
    public string CurrentRole => _role;
    public string CurrentKey => RoleKeys[_role];

    public event Action? RoleChanged;

    public void SetRole(string role)
    {
        if (!RoleKeys.ContainsKey(role))
        {
            return;
        }
        if (_role == role)
        {
            return;
        }
        _role = role;
        RoleChanged?.Invoke();
    }

    public HttpRequestMessage NewRequest(HttpMethod method, string path)
    {
        var req = new HttpRequestMessage(method, BaseUrl + path);
        req.Headers.Add("X-API-Key", CurrentKey);
        return req;
    }

    public async Task<ApiResult<T>> GetAsync<T>(string path) where T : class
    {
        using var client = _factory.CreateClient();
        client.Timeout = TimeSpan.FromSeconds(30);
        using var req = NewRequest(HttpMethod.Get, path);
        try
        {
            using var resp = await client.SendAsync(req);
            if (resp.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            {
                var err = await ReadBackendErrorAsync(resp);
                return ApiResult<T>.Unauthorized(err);
            }
            if (!resp.IsSuccessStatusCode)
            {
                return ApiResult<T>.Failure($"HTTP {(int)resp.StatusCode} {resp.StatusCode}");
            }
            var data = await resp.Content.ReadFromJsonAsync<T>();
            if (data == null)
            {
                return ApiResult<T>.Failure("empty response body");
            }
            return ApiResult<T>.Success(data);
        }
        catch (TaskCanceledException)
        {
            return ApiResult<T>.Failure("request timed out");
        }
        catch (Exception ex)
        {
            return ApiResult<T>.Failure(ex.Message);
        }
    }

    private static async Task<BackendError?> ReadBackendErrorAsync(HttpResponseMessage resp)
    {
        try
        {
            return await resp.Content.ReadFromJsonAsync<BackendError>();
        }
        catch
        {
            return null;
        }
    }

    public Task<ApiResult<MetricsDto>> GetMetricsAsync() => GetAsync<MetricsDto>("/metrics");
    public Task<ApiResult<ExceptionsDto>> GetExceptionsAsync() => GetAsync<ExceptionsDto>("/exceptions");
    public Task<ApiResult<PolicyComparisonDto>> GetComparisonAsync() => GetAsync<PolicyComparisonDto>("/compare-policy");
    public Task<ApiResult<PrescoreDto>> GetPrescoreAsync() => GetAsync<PrescoreDto>("/prescore");
    public Task<ApiResult<ChainStatusDto>> GetChainStatusAsync() => GetAsync<ChainStatusDto>("/chain-status");

    // POST /demo/tamper. The UI ignores the body — the badge flips in response
    // to the chain_status event arriving over the SSE stream, never this POST.
    public async Task<ApiResult<string>> PostTamperAsync()
    {
        using var client = _factory.CreateClient();
        client.Timeout = TimeSpan.FromSeconds(30);
        using var req = NewRequest(HttpMethod.Post, "/demo/tamper");
        try
        {
            using var resp = await client.SendAsync(req);
            if (resp.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            {
                var err = await ReadBackendErrorAsync(resp);
                return ApiResult<string>.Unauthorized(err);
            }
            if (!resp.IsSuccessStatusCode)
            {
                return ApiResult<string>.Failure($"HTTP {(int)resp.StatusCode} {resp.StatusCode}");
            }
            return ApiResult<string>.Success("");
        }
        catch (Exception ex)
        {
            return ApiResult<string>.Failure(ex.Message);
        }
    }

    public Task<ApiResult<SandboxDto>> GetSandboxAsync(string? scenario = null)
    {
        var q = string.IsNullOrWhiteSpace(scenario) ? "" : "?scenario=" + Uri.EscapeDataString(scenario);
        return GetAsync<SandboxDto>("/sandbox" + q);
    }

    public async Task<ApiResult<AdminActionResult>> PostAdminActionAsync(AdminActionRequest request)
    {
        using var client = _factory.CreateClient();
        client.Timeout = TimeSpan.FromSeconds(10);
        using var req = NewRequest(HttpMethod.Post, "/admin/action");
        req.Content = JsonContent.Create(request);
        try
        {
            using var resp = await client.SendAsync(req);
            if (resp.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            {
                var err = await ReadBackendErrorAsync(resp);
                return ApiResult<AdminActionResult>.Unauthorized(err);
            }
            if (!resp.IsSuccessStatusCode)
            {
                return ApiResult<AdminActionResult>.Failure($"HTTP {(int)resp.StatusCode}");
            }
            var data = await resp.Content.ReadFromJsonAsync<AdminActionResult>();
            if (data == null)
            {
                return ApiResult<AdminActionResult>.Failure("empty response");
            }
            return ApiResult<AdminActionResult>.Success(data);
        }
        catch (TaskCanceledException)
        {
            return ApiResult<AdminActionResult>.Failure("request timed out");
        }
        catch (Exception ex)
        {
            return ApiResult<AdminActionResult>.Failure(ex.Message);
        }
    }
}
