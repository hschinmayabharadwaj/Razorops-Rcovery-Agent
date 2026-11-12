namespace GatewayUI.Services;

// Request/response contracts for the Razorpay payment endpoints.

public sealed record CreateRazorpayOrderRequest(long Amount, string Currency = "INR", string? Receipt = null);

public sealed record RazorpayOrderResponse(string OrderId, long Amount, string Currency, string KeyId);

public sealed record VerifyRazorpayPaymentRequest(string OrderId, string PaymentId, string Signature);

public sealed record PaymentOperationResult(bool Ok, string? Message = null, string? EventId = null);
