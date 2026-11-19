using System.Net;
using GatewayUI.Services;
using GatewayUI.Tests.TestSupport;

namespace GatewayUI.Tests.Unit;

public sealed class GatewayApiServiceTests
{
    private static GatewayApiService NewApi(StubHttpHandler http) => new(new StubHttpClientFactory(http));

    [Fact]
    public void DefaultsToTheAdminRole()
    {
        var api = NewApi(StubHttpHandler.Default());

        Assert.Equal("admin", api.CurrentRole);
        Assert.Equal(GatewayApiService.AdminDemoKey, api.CurrentKey);
    }

    [Fact]
    public void SetRole_SwitchesCredentialAndNotifiesOnce()
    {
        var api = NewApi(StubHttpHandler.Default());
        var notifications = 0;
        api.RoleChanged += () => notifications++;

        api.SetRole("auditor");
        api.SetRole("auditor");

        Assert.Equal("auditor", api.CurrentRole);
        Assert.Equal("audit_key_demo", api.CurrentKey);
        Assert.Equal(1, notifications);
    }

    [Fact]
    public void SetRole_IgnoresUnknownRoles()
    {
        var api = NewApi(StubHttpHandler.Default());
        var notifications = 0;
        api.RoleChanged += () => notifications++;

        api.SetRole("superuser");

        Assert.Equal("admin", api.CurrentRole);
        Assert.Equal(0, notifications);
    }

    [Fact]
    public async Task Requests_CarryTheCurrentRolesApiKey()
    {
        var http = new StubHttpHandler(_ => StubHttpHandler.Json(HttpStatusCode.OK, """{"valid":true,"entries":3,"brokenAt":null}"""));
        var api = NewApi(http);
        api.SetRole("operator");

        var result = await api.GetChainStatusAsync();

        Assert.True(result.Ok);
        Assert.Equal(3, result.Data!.Entries);
        var request = Assert.Single(http.Requests);
        Assert.Equal("op_key_demo", request.ApiKey);
        Assert.Equal("/chain-status", request.Uri.AbsolutePath);
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.Forbidden)]
    public async Task Get_MapsAuthFailuresToDenied_WithTheBackendReason(HttpStatusCode status)
    {
        var http = new StubHttpHandler(_ => StubHttpHandler.Json(status, """{"error":"Forbidden","reason":"forbidden_for_role","actor":"audit-demo","action":"tune_sandbox"}"""));
        var api = NewApi(http);

        var result = await api.GetSandboxAsync();

        Assert.True(result.AuthDenied);
        Assert.Equal("forbidden_for_role", result.Denied!.Reason);
        Assert.Equal("tune_sandbox", result.Denied.Action);
    }

    [Fact]
    public async Task Get_MapsServerErrorsToFailure()
    {
        var api = NewApi(new StubHttpHandler(_ => new HttpResponseMessage(HttpStatusCode.InternalServerError)));

        var result = await api.GetMetricsAsync();

        Assert.True(result.Failed);
        Assert.Contains("500", result.Error);
    }

    [Fact]
    public async Task Get_MapsNetworkErrorsToFailure_InsteadOfThrowing()
    {
        var api = NewApi(new StubHttpHandler(_ => throw new HttpRequestException("connection refused")));

        var result = await api.GetMetricsAsync();

        Assert.True(result.Failed);
        Assert.Equal("connection refused", result.Error);
    }

    [Fact]
    public async Task GetSandbox_EscapesTheScenarioQueryParameter()
    {
        var http = new StubHttpHandler(_ => StubHttpHandler.Json(HttpStatusCode.OK, """{"scenarios":[],"lockedInvariant":true}"""));
        var api = NewApi(http);

        await api.GetSandboxAsync("high incentive&x=1");

        var request = Assert.Single(http.Requests);
        Assert.Equal("?scenario=high%20incentive%26x%3D1", request.Uri.Query);
    }

    [Fact]
    public async Task GetWorkQueue_ReadsRankedItemsAndEligibility()
    {
        var http = new StubHttpHandler(_ => StubHttpHandler.Json(HttpStatusCode.OK, """
            {"items":[
              {"rank":1,"eventId":"evt_a","flow":"failed_subscription","failureClass":"customer_side","amountRupees":1000,
               "probability":0.8,"expectedRupees":800,"riskTier":"low","eligibility":{"eligible":true,"state":"retrying"},
               "recommendation":"remind the customer, then retry",
               "explanationPath":[{"level":"flow","key":"failed_subscription","observations":40,"observedRate":0.6,"estimate":0.61}]},
              {"rank":2,"eventId":"evt_b","flow":"mandate_retry","failureClass":"blocked","amountRupees":500,
               "probability":0.0,"expectedRupees":0,"eligibility":{"eligible":false,"reason":"locked compliance rule","blockingRule":"mandate_revoked_escalate","state":"escalated"}}
            ],"eligibleCount":1,"blockedCount":1,"expectedRupees":800,"failureClassCounts":{"customer_side":1,"blocked":1}}
            """));
        var api = NewApi(http);

        var result = await api.GetWorkQueueAsync();

        Assert.True(result.Ok);
        var items = result.Data!.Items!;
        Assert.Equal(["evt_a", "evt_b"], items.Select(i => i.EventId));
        Assert.True(items[0].Eligibility!.Eligible);
        Assert.Equal("mandate_revoked_escalate", items[1].Eligibility!.BlockingRule);
        Assert.Equal(0.61, Assert.Single(items[0].ExplanationPath!).Estimate);
        Assert.Equal("/intelligence/queue", Assert.Single(http.Requests).Uri.AbsolutePath);
    }

    [Fact]
    public async Task GetSignalProfile_EscapesTheEventId()
    {
        var http = new StubHttpHandler(_ => StubHttpHandler.Json(HttpStatusCode.OK, """{"eventId":"a b&c","probability":0.4}"""));
        var api = NewApi(http);

        var result = await api.GetSignalProfileAsync("a b&c");

        Assert.Equal(0.4, result.Data!.Probability);
        var request = Assert.Single(http.Requests);
        Assert.Equal("/intelligence/profile", request.Uri.AbsolutePath);
        Assert.Equal("?eventId=a%20b%26c", request.Uri.Query);
    }

    [Fact]
    public async Task GetRecoveryProgress_ReturnsEmptyBucketsForMissingOutcomes()
    {
        var http = new StubHttpHandler(_ => StubHttpHandler.Json(HttpStatusCode.OK,
            """{"totalEvents":2,"totalAtRiskRupees":300,"outcomes":{"recovered":{"count":1,"rupees":100}},"inFlightStates":{}}"""));
        var api = NewApi(http);

        var result = await api.GetRecoveryProgressAsync();

        Assert.Equal(new GatewayUI.Models.ProgressBucketDto(1, 100), result.Data!.Bucket("recovered"));
        Assert.Equal(new GatewayUI.Models.ProgressBucketDto(0, 0), result.Data.Bucket("escalated"));
    }

    [Theory]
    [InlineData("model", "/intelligence/model")]
    [InlineData("health", "/intelligence/health")]
    public async Task DecisionLayerCalls_HitTheirGoRoutes(string call, string path)
    {
        var http = new StubHttpHandler(_ => StubHttpHandler.Json(HttpStatusCode.OK, "{}"));
        var api = NewApi(http);

        var ok = call == "model" ? (await api.GetModelCardAsync()).Ok : (await api.GetHealthAsync()).Ok;

        Assert.True(ok);
        Assert.Equal(path, Assert.Single(http.Requests).Uri.AbsolutePath);
    }

    [Fact]
    public async Task PostAdminAction_ReturnsTheRefusalFromTheBackend()
    {
        var http = new StubHttpHandler(_ => StubHttpHandler.Json(HttpStatusCode.OK,
            """{"ok":false,"eventId":"evt_1","decision":"none","state":"suppressed","outcome":"REFUSED: locked","refused":true,"refusedBy":"fraud_suppress","refusedReason":"locked rule fraud_suppress blocks retry"}"""));
        var api = NewApi(http);

        var result = await api.PostAdminActionAsync(new GatewayUI.Models.AdminActionRequest("evt_1", "nudge_retry"));

        Assert.True(result.Ok);
        Assert.False(result.Data!.Ok);
        Assert.Equal("fraud_suppress", result.Data.RefusedBy);
        var request = Assert.Single(http.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Contains("\"action\":\"nudge_retry\"", request.Body);
    }
}
