using System.Text.Json;
using System.Threading.RateLimiting;
using GatewayUI.Services;
using Microsoft.AspNetCore.Http.Features;

namespace GatewayUI.Endpoints;

/// <summary>
/// HTTP surface for the Razorpay test checkout: order creation, payment
/// signature verification and the webhook receiver. Business logic lives in
/// <see cref="RazorpayPaymentService"/>; this class only maps HTTP to it.
/// </summary>
public static class PaymentEndpoints
{
    public const string OrderRoute = "/api/payments/razorpay/order";
    public const string VerifyRoute = "/api/payments/razorpay/verify";
    public const string WebhookRoute = "/webhooks/razorpay";

    public const string RateLimitPolicy = "payments";
    public const string RequestsPerMinuteSetting = "Payments:RequestsPerMinute";
    public const int DefaultRequestsPerMinute = 20;

    // Razorpay webhook payloads are a few KB; 1 MB is a generous ceiling.
    public const long MaxWebhookBodyBytes = 1024 * 1024;

    private const string SignatureHeader = "X-Razorpay-Signature";
    private const string EventIdHeader = "X-Razorpay-Event-Id";
    private const string PaymentsUnavailable = "Payments are not available right now.";
    private const string LogCategory = "GatewayUI.Endpoints.PaymentEndpoints";

    /// <summary>
    /// The order/verify endpoints are anonymous and call the merchant's
    /// Razorpay account, so cap how often one client address can hit them.
    /// </summary>
    public static IServiceCollection AddPaymentRateLimiting(this IServiceCollection services)
    {
        services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.AddPolicy(RateLimitPolicy, context =>
            {
                var configuration = context.RequestServices.GetRequiredService<IConfiguration>();
                var permitLimit = Math.Max(1, configuration.GetValue(RequestsPerMinuteSetting, DefaultRequestsPerMinute));
                return RateLimitPartition.GetFixedWindowLimiter(
                    context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                    _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = permitLimit,
                        Window = TimeSpan.FromMinutes(1),
                        QueueLimit = 0,
                    });
            });
        });
        return services;
    }

    public static IEndpointRouteBuilder MapPaymentEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost(OrderRoute, CreateOrderAsync).RequireRateLimiting(RateLimitPolicy);
        endpoints.MapPost(VerifyRoute, VerifyPaymentAsync).RequireRateLimiting(RateLimitPolicy);
        endpoints.MapPost(WebhookRoute, ReceiveWebhookAsync);
        return endpoints;
    }

    private static async Task<IResult> CreateOrderAsync(
        CreateRazorpayOrderRequest request, RazorpayPaymentService payments, ILoggerFactory loggers, CancellationToken cancellationToken)
    {
        try
        {
            var result = await payments.CreateOrderAsync(request, cancellationToken);
            return result.Order is null
                ? Results.BadRequest(new { error = result.Error })
                : Results.Ok(result.Order);
        }
        catch (InvalidOperationException ex)
        {
            loggers.CreateLogger(LogCategory).LogError(ex, "Razorpay order endpoint is not configured");
            return Unavailable();
        }
    }

    private static async Task<IResult> VerifyPaymentAsync(
        VerifyRazorpayPaymentRequest request, RazorpayPaymentService payments, ILoggerFactory loggers, CancellationToken cancellationToken)
    {
        try
        {
            var result = await payments.VerifyPaymentAsync(request, cancellationToken);
            return result.Ok ? Results.Ok(result) : Results.BadRequest(result);
        }
        catch (InvalidOperationException ex)
        {
            loggers.CreateLogger(LogCategory).LogError(ex, "Razorpay verify endpoint is not configured");
            return Unavailable();
        }
    }

    private static async Task<IResult> ReceiveWebhookAsync(
        HttpRequest request, RazorpayPaymentService payments, ILoggerFactory loggers, CancellationToken cancellationToken)
    {
        var signature = request.Headers[SignatureHeader].ToString();
        if (string.IsNullOrWhiteSpace(signature))
        {
            return Results.Unauthorized();
        }

        // Bound the body BEFORE reading it: it is buffered in full ahead of the
        // HMAC check, so an unbounded body is a memory-exhaustion vector.
        var rawBody = await ReadBoundedBodyAsync(request, cancellationToken);
        if (rawBody is null)
        {
            return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
        }

        try
        {
            var result = await payments.ProcessWebhookAsync(signature, rawBody, request.Headers[EventIdHeader].ToString(), cancellationToken);
            return result.Ok ? Results.Ok(result) : Results.Unauthorized();
        }
        catch (JsonException)
        {
            return Results.BadRequest(new { error = "Webhook body is not valid JSON." });
        }
        catch (InvalidOperationException ex)
        {
            loggers.CreateLogger(LogCategory).LogError(ex, "Razorpay webhook could not be processed");
            return Unavailable();
        }
    }

    // Reads the request body as text, or returns null when it exceeds
    // MaxWebhookBodyBytes. The limit is enforced while streaming, so it holds
    // whether or not the client declared a Content-Length.
    private static async Task<string?> ReadBoundedBodyAsync(HttpRequest request, CancellationToken cancellationToken)
    {
        if (request.ContentLength is > MaxWebhookBodyBytes)
        {
            return null;
        }
        var sizeFeature = request.HttpContext.Features.Get<IHttpMaxRequestBodySizeFeature>();
        if (sizeFeature is { IsReadOnly: false })
        {
            sizeFeature.MaxRequestBodySize = MaxWebhookBodyBytes;
        }

        using var buffer = new MemoryStream();
        var chunk = new byte[16 * 1024];
        try
        {
            int read;
            while ((read = await request.Body.ReadAsync(chunk, cancellationToken)) > 0)
            {
                if (buffer.Length + read > MaxWebhookBodyBytes)
                {
                    return null;
                }
                buffer.Write(chunk, 0, read);
            }
        }
        catch (BadHttpRequestException)
        {
            return null;
        }
        return System.Text.Encoding.UTF8.GetString(buffer.GetBuffer(), 0, (int)buffer.Length);
    }

    private static IResult Unavailable() =>
        Results.Problem(PaymentsUnavailable, statusCode: StatusCodes.Status503ServiceUnavailable);
}
