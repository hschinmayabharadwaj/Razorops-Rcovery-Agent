using System.Globalization;

namespace GatewayUI.Components.Shared;

/// <summary>Display formatting shared by the dashboard pages.</summary>
public static class Fmt
{
    private static readonly CultureInfo India = new("en-IN");

    public static string Pct(double rate, int decimals = 1) =>
        (rate * 100).ToString("F" + decimals, CultureInfo.InvariantCulture) + "%";

    public static string Rupees(double rupees) => rupees.ToString("C0", India);

    public static string Number(double value, string format = "0.000") =>
        value.ToString(format, CultureInfo.InvariantCulture);

    /// <summary>"failed_subscription" -> "failed subscription".</summary>
    public static string Words(string? snake) =>
        string.IsNullOrWhiteSpace(snake) ? "—" : snake.Replace('_', ' ');

    public static string FailureClassBadge(string? failureClass) => failureClass switch
    {
        "route_influenceable" => "bg-primary",
        "customer_side" => "bg-warning text-dark",
        "customer_left" => "bg-info text-dark",
        "blocked" => "bg-danger",
        _ => "bg-secondary",
    };

    public static string HealthBadge(string? status) => status switch
    {
        "healthy" => "bg-success",
        "degraded" => "bg-danger",
        _ => "bg-secondary",
    };

    public static string RiskBadge(string? tier) => tier switch
    {
        "high" => "bg-danger",
        "medium" => "bg-warning text-dark",
        "low" => "bg-success",
        _ => "bg-secondary",
    };
}
