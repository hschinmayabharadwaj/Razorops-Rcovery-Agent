using System.Net;
using System.Text;
using GatewayUI.Models;
using GatewayUI.Services;
using GatewayUI.Tests.TestSupport;

namespace GatewayUI.Tests.Unit;

public sealed class AuditStreamServiceTests
{
    [Fact]
    public void ParseEvent_ReadsAnAuditEntry()
    {
        const string json = """{"eventType":"audit","eventId":"evt_1","flow":"mandate_retry","state":"recovered","amount":49900,"hash":"abc"}""";

        var parsed = AuditStreamService.ParseEvent(json);

        var audit = Assert.IsType<AuditStreamEvent>(parsed);
        Assert.Equal("evt_1", audit.Entry.EventId);
        Assert.Equal("recovered", audit.Entry.State);
        Assert.Equal(49900, audit.Entry.Amount);
    }

    [Fact]
    public void ParseEvent_ReadsABrokenChainStatus()
    {
        var parsed = AuditStreamService.ParseEvent("""{"eventType":"chain_status","valid":false,"entries":188,"brokenAt":4}""");

        var status = Assert.IsType<ChainStatusStreamEvent>(parsed);
        Assert.Equal(new ChainStatusDto(false, 188, 4), status.Status);
    }

    [Fact]
    public void ParseEvent_TreatsNullBrokenAtAsNoBreak()
    {
        var parsed = AuditStreamService.ParseEvent("""{"eventType":"chain_status","valid":true,"entries":10,"brokenAt":null}""");

        var status = Assert.IsType<ChainStatusStreamEvent>(parsed);
        Assert.Null(status.Status.BrokenAt);
    }

    [Theory]
    [InlineData("not json")]
    [InlineData("{\"eventType\":")]
    public void ParseEvent_ReturnsNullForMalformedPayloads(string payload)
    {
        Assert.Null(AuditStreamService.ParseEvent(payload));
    }

    private static string Frame(string eventId, string hash) =>
        $"data: {{\"eventType\":\"audit\",\"eventId\":\"{eventId}\",\"hash\":\"{hash}\"}}\n\n";

    private static async Task WaitUntilAsync(Func<bool> condition, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (!condition())
        {
            if (DateTime.UtcNow > deadline)
            {
                throw new TimeoutException("condition was not met in time");
            }
            await Task.Delay(25);
        }
    }

    [Fact]
    public async Task Stream_DeliversEachEntryOnce_EvenWhenTheServerReplaysHistoryOnReconnect()
    {
        // Arrange: every connection replays the same two-entry history and then
        // closes, exactly like the Go /events endpoint after a dropped stream.
        var connections = 0;
        var http = new StubHttpHandler(_ =>
        {
            Interlocked.Increment(ref connections);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(Frame("evt_1", "h1") + Frame("evt_2", "h2"), Encoding.UTF8, "text/event-stream")
            };
        });
        var factory = new StubHttpClientFactory(http);
        var service = new AuditStreamService(new GatewayApiService(factory), factory);
        var received = new List<string?>();
        service.Subscribe(ev =>
        {
            if (ev is AuditStreamEvent a)
            {
                lock (received)
                {
                    received.Add(a.Entry.EventId);
                }
            }
        });

        // Act: run until the service has reconnected at least once.
        await service.StartAsync(CancellationToken.None);
        try
        {
            await WaitUntilAsync(() => Volatile.Read(ref connections) >= 2, TimeSpan.FromSeconds(15));
            await Task.Delay(200);
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
        }

        // Assert
        lock (received)
        {
            Assert.Equal(["evt_1", "evt_2"], received);
        }
    }

    [Fact]
    public async Task LateSubscriber_ReceivesBufferedHistory()
    {
        var http = new StubHttpHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(Frame("evt_1", "h1"), Encoding.UTF8, "text/event-stream")
        });
        var factory = new StubHttpClientFactory(http);
        var service = new AuditStreamService(new GatewayApiService(factory), factory);
        await service.StartAsync(CancellationToken.None);
        try
        {
            await WaitUntilAsync(() => http.Requests.Count >= 1, TimeSpan.FromSeconds(10));
            await Task.Delay(200);

            var replayed = new List<StreamEvent>();
            service.Subscribe(replayed.Add);

            var audit = Assert.IsType<AuditStreamEvent>(Assert.Single(replayed));
            Assert.Equal("evt_1", audit.Entry.EventId);
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task Stream_ReportsDenied_WhenTheBackendRejectsTheCredential()
    {
        var http = new StubHttpHandler(_ => new HttpResponseMessage(HttpStatusCode.Forbidden));
        var factory = new StubHttpClientFactory(http);
        var service = new AuditStreamService(new GatewayApiService(factory), factory);
        var phases = new List<StreamPhase>();
        service.StatusChanged += status =>
        {
            lock (phases)
            {
                phases.Add(status.Phase);
            }
        };

        await service.StartAsync(CancellationToken.None);
        try
        {
            await WaitUntilAsync(() => service.CurrentStatus.Phase == StreamPhase.Denied, TimeSpan.FromSeconds(10));
        }
        finally
        {
            await service.StopAsync(CancellationToken.None);
        }

        lock (phases)
        {
            Assert.Contains(StreamPhase.Denied, phases);
        }
    }
}
