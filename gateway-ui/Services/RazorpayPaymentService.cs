using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace GatewayUI.Services;

public sealed class RazorpayPaymentService
{
    // Order amount bounds in paise (₹1 .. ₹5,00,000). The upper bound stops an
    // anonymous caller from minting arbitrarily large orders on the merchant key.
    public const long MinOrderAmountPaise = 100;
    public const long MaxOrderAmountPaise = 50_000_000;
    public const int MaxReceiptLength = 40;
    // Razorpay ids are short ("order_...", "pay_..."); signatures are 64 hex chars.
    public const int MaxIdentifierLength = 64;
    public const int MaxSignatureLength = 128;

    private readonly IHttpClientFactory _clientFactory;
    private readonly IConfiguration _configuration;
    private readonly PaymentAuditService _audit;
    private readonly ILogger<RazorpayPaymentService> _logger;
    private readonly ConcurrentDictionary<string, byte> _processedWebhookEvents = new();

    public RazorpayPaymentService(IHttpClientFactory clientFactory, IConfiguration configuration, PaymentAuditService audit, ILogger<RazorpayPaymentService> logger)
    {
        _clientFactory = clientFactory;
        _configuration = configuration;
        _audit = audit;
        _logger = logger;
    }

    public string KeyId => RequiredSetting("RAZORPAY_KEY_ID", "Razorpay:KeyId");

    public async Task<(RazorpayOrderResponse? Order, string? Error)> CreateOrderAsync(CreateRazorpayOrderRequest request, CancellationToken cancellationToken)
    {
        if (request.Amount < MinOrderAmountPaise)
        {
            return (null, $"Amount must be at least {MinOrderAmountPaise} paise.");
        }
        if (request.Amount > MaxOrderAmountPaise)
        {
            return (null, $"Amount must be at most {MaxOrderAmountPaise} paise.");
        }
        if (request.Receipt is { Length: > MaxReceiptLength })
        {
            return (null, $"Receipt must be at most {MaxReceiptLength} characters.");
        }
        if (!string.Equals(request.Currency, "INR", StringComparison.OrdinalIgnoreCase))
        {
            return (null, "This first integration supports INR only.");
        }

        var keySecret = RequiredSetting("RAZORPAY_KEY_SECRET", "Razorpay:KeySecret");
        var payload = new
        {
            amount = request.Amount,
            currency = request.Currency.ToUpperInvariant(),
            receipt = string.IsNullOrWhiteSpace(request.Receipt) ? $"rcpt_{Guid.NewGuid():N}" : request.Receipt,
            notes = new { source = "razorops" }
        };

        using var client = _clientFactory.CreateClient();
        using var message = new HttpRequestMessage(HttpMethod.Post, "https://api.razorpay.com/v1/orders")
        {
            Content = JsonContent.Create(payload)
        };
        var basic = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{KeyId}:{keySecret}"));
        message.Headers.Authorization = new AuthenticationHeaderValue("Basic", basic);

        try
        {
            using var response = await client.SendAsync(message, cancellationToken);
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Razorpay order creation failed with status {Status}", (int)response.StatusCode);
                return (null, $"Razorpay order creation failed ({(int)response.StatusCode}).");
            }

            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            return (new RazorpayOrderResponse(
                root.GetProperty("id").GetString()!,
                root.GetProperty("amount").GetInt64(),
                root.GetProperty("currency").GetString()!,
                KeyId), null);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return (null, "Razorpay request timed out.");
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            // Log the detail server-side; never echo exception text to the browser.
            _logger.LogError(ex, "Razorpay order request failed");
            return (null, "Razorpay request failed. Please try again.");
        }
    }

    public async Task<PaymentOperationResult> VerifyPaymentAsync(VerifyRazorpayPaymentRequest request, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.OrderId) || string.IsNullOrWhiteSpace(request.PaymentId) || string.IsNullOrWhiteSpace(request.Signature))
        {
            return new(false, "Order ID, payment ID, and signature are required.");
        }
        // These values are written to the audit log, so bound them before use.
        if (request.OrderId.Length > MaxIdentifierLength || request.PaymentId.Length > MaxIdentifierLength
            || request.Signature.Length > MaxSignatureLength
            || !IsSafeIdentifier(request.OrderId) || !IsSafeIdentifier(request.PaymentId))
        {
            return new(false, "Order ID, payment ID, or signature is malformed.");
        }

        var secret = RequiredSetting("RAZORPAY_KEY_SECRET", "Razorpay:KeySecret");
        var expected = HmacHex(secret, $"{request.OrderId}|{request.PaymentId}");
        var valid = CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(expected),
            Encoding.UTF8.GetBytes(request.Signature));
        var eventId = $"payment.verified.{request.PaymentId}";
        await _audit.AppendAsync(eventId, "payment.verified", valid ? "verified" : "rejected", new
        {
            orderId = request.OrderId,
            paymentId = request.PaymentId,
            valid
        }, cancellationToken);

        return valid
            ? new(true, "Payment signature verified.", eventId)
            : new(false, "Payment signature did not match.", eventId);
    }

    public async Task<PaymentOperationResult> ProcessWebhookAsync(string signature, string rawBody, string? razorpayEventId, CancellationToken cancellationToken)
    {
        var secret = RequiredSetting("RAZORPAY_WEBHOOK_SECRET", "Razorpay:WebhookSecret");
        var expected = HmacHex(secret, rawBody);
        var valid = CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(expected),
            Encoding.UTF8.GetBytes(signature.Trim()));
        if (!valid)
        {
            return new(false, "Invalid Razorpay webhook signature.");
        }

        using var document = JsonDocument.Parse(rawBody);
        var root = document.RootElement;
        var eventName = root.TryGetProperty("event", out var eventProperty) ? eventProperty.GetString() ?? "unknown" : "unknown";
        var entityId = root.TryGetProperty("payload", out var payload) && payload.ValueKind == JsonValueKind.Object
            && payload.TryGetProperty("payment", out var payment) && payment.ValueKind == JsonValueKind.Object
            && payment.TryGetProperty("entity", out var entity) && entity.ValueKind == JsonValueKind.Object
            && entity.TryGetProperty("id", out var paymentId) && paymentId.ValueKind == JsonValueKind.String
            ? paymentId.GetString()
            : null;

        // Idempotency key. Razorpay's X-Razorpay-Event-Id is unique per event and
        // stable across its retries. Without it, fall back to event name + payment
        // id: the payment id ALONE is not enough, because one payment legitimately
        // produces several events (authorized -> captured, failed -> captured).
        string eventId;
        if (!string.IsNullOrWhiteSpace(razorpayEventId) && razorpayEventId.Length <= MaxIdentifierLength && IsSafeIdentifier(razorpayEventId))
        {
            eventId = razorpayEventId;
        }
        else if (!string.IsNullOrWhiteSpace(entityId))
        {
            eventId = $"{eventName}:{entityId}";
        }
        else
        {
            // No stable identity at all: hash the verified body so a retry of the
            // same delivery still deduplicates.
            eventId = "webhook." + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(rawBody))).ToLowerInvariant()[..32];
        }

        if (!_processedWebhookEvents.TryAdd(eventId, 0))
        {
            return new(true, "Webhook already processed.", eventId);
        }

        try
        {
            await _audit.AppendAsync(eventId, eventName, "accepted", new { eventName, paymentId = entityId }, cancellationToken);
        }
        catch
        {
            // The event was not recorded: release the claim so Razorpay's retry
            // is processed instead of being reported as a duplicate.
            _processedWebhookEvents.TryRemove(eventId, out _);
            throw;
        }
        return new(true, "Webhook accepted.", eventId);
    }

    // Letters, digits and the few separators Razorpay ids use. Keeps control
    // characters and markup out of the audit log.
    private static bool IsSafeIdentifier(string value)
    {
        foreach (var c in value)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.' or ':'))
            {
                return false;
            }
        }
        return value.Length > 0;
    }

    private string RequiredSetting(string environmentName, string configurationName)
    {
        var value = Environment.GetEnvironmentVariable(environmentName);
        if (!string.IsNullOrWhiteSpace(value))
        {
            return value;
        }
        value = _configuration[configurationName];
        if (!string.IsNullOrWhiteSpace(value))
        {
            return value;
        }
        throw new InvalidOperationException($"Payment configuration '{environmentName}' is not set.");
    }

    private static string HmacHex(string secret, string value)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
    }
}
