using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace GatewayUI.Tests.TestSupport;

/// <summary>
/// Fixed, obviously-fake Razorpay credentials for the whole test assembly.
/// The app reads these from environment variables first, so they are pinned
/// here before any test runs — a developer's real RAZORPAY_* values can never
/// leak into (or break) a test run.
/// </summary>
public static class TestSecrets
{
    public const string KeyId = "rzp_test_unit_key";
    public const string KeySecret = "unit_test_key_secret";
    public const string WebhookSecret = "unit_test_webhook_secret";

    [ModuleInitializer]
    public static void Apply()
    {
        Environment.SetEnvironmentVariable("RAZORPAY_KEY_ID", KeyId);
        Environment.SetEnvironmentVariable("RAZORPAY_KEY_SECRET", KeySecret);
        Environment.SetEnvironmentVariable("RAZORPAY_WEBHOOK_SECRET", WebhookSecret);
    }

    /// <summary>Lower-case hex HMAC-SHA256, the scheme Razorpay signs with.</summary>
    public static string Sign(string secret, string payload)
    {
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        return Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(payload))).ToLowerInvariant();
    }

    /// <summary>A minimal Razorpay payment webhook payload.</summary>
    public static string WebhookBody(string eventName, string paymentId) =>
        "{\"event\":\"" + eventName + "\",\"payload\":{\"payment\":{\"entity\":{\"id\":\"" + paymentId + "\"}}}}";

    public static string SignWebhook(string body) => Sign(WebhookSecret, body);

    public static string SignPayment(string orderId, string paymentId) => Sign(KeySecret, $"{orderId}|{paymentId}");
}
