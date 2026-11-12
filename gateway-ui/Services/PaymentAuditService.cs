using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace GatewayUI.Services;

/// <summary>Result of re-verifying the payment audit hash chain.</summary>
public sealed record PaymentChainVerification(bool Valid, int Entries, int? BrokenAtIndex);

/// <summary>
/// Append-only, hash-chained JSONL audit log for payment integration events
/// (order verification + Razorpay webhooks). Each line commits to the previous
/// line's hash, so any edit or removal is detectable with <see cref="VerifyFileAsync"/>.
/// </summary>
public sealed class PaymentAuditService
{
    public const string GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000";
    private const string DefaultAuditPath = "../data/payment-webhooks.jsonl";
    private const string DefaultGoBackendUrl = "http://localhost:8090";
    private static readonly TimeSpan ForwardTimeout = TimeSpan.FromSeconds(5);

    private readonly string _path;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly IHttpClientFactory _clientFactory;
    private readonly ILogger<PaymentAuditService> _logger;
    private readonly string _goStreamBaseUrl;
    private string _previousHash = GenesisHash;
    private bool _tailLoaded;

    public PaymentAuditService(IHostEnvironment environment, IConfiguration configuration, IHttpClientFactory clientFactory, ILogger<PaymentAuditService> logger)
    {
        var configured = configuration["PaymentAuditPath"] ?? DefaultAuditPath;
        _path = Path.GetFullPath(Path.Combine(environment.ContentRootPath, configured));
        _clientFactory = clientFactory;
        _logger = logger;
        _goStreamBaseUrl = configuration["GO_BACKEND_URL"] ?? DefaultGoBackendUrl;
    }

    /// <summary>Absolute path of the audit file.</summary>
    public string AuditPath => _path;

    public async Task AppendAsync(string eventId, string eventType, string state, object details, CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            if (!_tailLoaded)
            {
                // Resume the chain from the existing file. Starting from genesis
                // after every restart would break the hash chain mid-file.
                _previousHash = await ReadTailHashAsync(cancellationToken) ?? GenesisHash;
                _tailLoaded = true;
            }
            var entry = new PaymentAuditEntry(eventId, DateTimeOffset.UtcNow, eventType, state, details, _previousHash, "");
            var hash = ComputeHash(_previousHash, JsonSerializer.Serialize(entry));
            var line = JsonSerializer.Serialize(entry with { Hash = hash }) + Environment.NewLine;
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            await File.AppendAllTextAsync(_path, line, Encoding.UTF8, cancellationToken);
            _previousHash = hash;
        }
        finally
        {
            _gate.Release();
        }

        // Best-effort forward to Go stream server so the event appears on the
        // live SSE audit stream. Failures are logged but never propagated — the
        // local hash chain is the source of truth for payment audit.
        _ = ForwardToGoAsync(eventId, eventType, state, details);
    }

    /// <summary>
    /// Recomputes every hash in an audit file and reports the first broken
    /// line (0-based), mirroring the Go <c>VerifyChain</c>. A missing file is a
    /// valid, empty chain.
    /// </summary>
    public static async Task<PaymentChainVerification> VerifyFileAsync(string path, CancellationToken cancellationToken = default)
    {
        if (!File.Exists(path))
        {
            return new(true, 0, null);
        }

        var expectedPrevious = GenesisHash;
        var index = 0;
        await foreach (var line in File.ReadLinesAsync(path, Encoding.UTF8, cancellationToken))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }
            if (!TryReadHashes(line, out var previous, out var hash)
                || previous != expectedPrevious
                || hash != ComputeHash(previous, BlankHash(line, hash)))
            {
                return new(false, index, index);
            }
            expectedPrevious = hash;
            index++;
        }
        return new(true, index, null);
    }

    // hash = sha256(prevHash + the entry serialized with an empty hash field).
    private static string ComputeHash(string previousHash, string unsignedJson) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(previousHash + unsignedJson))).ToLowerInvariant();

    // Rebuilds the exact "unsigned" text that was hashed: the stored line with
    // its trailing hash value blanked.
    private static string BlankHash(string line, string hash)
    {
        var signed = $"\"hash\":\"{hash}\"}}";
        return line.EndsWith(signed, StringComparison.Ordinal)
            ? string.Concat(line.AsSpan(0, line.Length - signed.Length), "\"hash\":\"\"}")
            : line;
    }

    private static bool TryReadHashes(string line, out string previous, out string hash)
    {
        previous = "";
        hash = "";
        try
        {
            using var document = JsonDocument.Parse(line);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object
                || !root.TryGetProperty("prevHash", out var previousElement) || previousElement.ValueKind != JsonValueKind.String
                || !root.TryGetProperty("hash", out var hashElement) || hashElement.ValueKind != JsonValueKind.String)
            {
                return false;
            }
            previous = previousElement.GetString()!;
            hash = hashElement.GetString()!;
            return hash.Length > 0;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    // Returns the hash of the last entry in the audit file, or null when the
    // file is missing or empty. A tail that cannot be parsed throws: silently
    // restarting from genesis would hide a corrupted log.
    private async Task<string?> ReadTailHashAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_path))
        {
            return null;
        }
        string? last = null;
        await foreach (var line in File.ReadLinesAsync(_path, Encoding.UTF8, cancellationToken))
        {
            if (!string.IsNullOrWhiteSpace(line))
            {
                last = line;
            }
        }
        if (last is null)
        {
            return null;
        }
        if (TryReadHashes(last, out _, out var hash))
        {
            return hash;
        }
        throw new InvalidOperationException("Payment audit log tail is unreadable; refusing to extend a corrupted chain.");
    }

    private async Task ForwardToGoAsync(string eventId, string eventType, string state, object details)
    {
        try
        {
            using var client = _clientFactory.CreateClient();
            client.Timeout = ForwardTimeout;
            var payload = new
            {
                eventId,
                eventType,
                state,
                details = JsonSerializer.Serialize(details)
            };
            using var request = new HttpRequestMessage(HttpMethod.Post, $"{_goStreamBaseUrl}/payment-event")
            {
                Content = JsonContent.Create(payload)
            };
            // Use the admin key so the Go auth gate accepts the write.
            request.Headers.Add("X-API-Key", GatewayApiService.AdminDemoKey);
            using var response = await client.SendAsync(request);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Forward to Go /payment-event returned {Status}", (int)response.StatusCode);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to forward payment event {EventId} to Go stream server", eventId);
        }
    }

    private sealed record PaymentAuditEntry(
        [property: JsonPropertyName("eventId")] string EventId,
        [property: JsonPropertyName("timestamp")] DateTimeOffset Timestamp,
        [property: JsonPropertyName("eventType")] string EventType,
        [property: JsonPropertyName("state")] string State,
        [property: JsonPropertyName("details")] object Details,
        [property: JsonPropertyName("prevHash")] string PreviousHash,
        [property: JsonPropertyName("hash")] string Hash);
}
