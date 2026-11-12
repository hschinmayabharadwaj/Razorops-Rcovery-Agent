using System.Text.Json;
using GatewayUI.Services;
using GatewayUI.Tests.TestSupport;

namespace GatewayUI.Tests.Unit;

public sealed class PaymentAuditServiceTests : IDisposable
{
    private readonly TempAuditFile _audit = new();

    public void Dispose() => _audit.Dispose();

    private static (string PrevHash, string Hash) Hashes(string line)
    {
        using var document = JsonDocument.Parse(line);
        return (document.RootElement.GetProperty("prevHash").GetString()!, document.RootElement.GetProperty("hash").GetString()!);
    }

    [Fact]
    public async Task Append_StartsFromGenesisAndLinksEachEntryToThePrevious()
    {
        var service = _audit.NewAuditService();

        await service.AppendAsync("evt_1", "payment.captured", "accepted", new { n = 1 }, CancellationToken.None);
        await service.AppendAsync("evt_2", "payment.captured", "accepted", new { n = 2 }, CancellationToken.None);
        await service.AppendAsync("evt_3", "payment.failed", "accepted", new { n = 3 }, CancellationToken.None);

        var lines = _audit.ReadLines();
        Assert.Equal(3, lines.Length);
        Assert.Equal(PaymentAuditService.GenesisHash, Hashes(lines[0]).PrevHash);
        Assert.Equal(Hashes(lines[0]).Hash, Hashes(lines[1]).PrevHash);
        Assert.Equal(Hashes(lines[1]).Hash, Hashes(lines[2]).PrevHash);
    }

    [Fact]
    public async Task Append_ResumesTheChainAfterARestart()
    {
        await _audit.NewAuditService().AppendAsync("evt_1", "payment.captured", "accepted", new { }, CancellationToken.None);

        // A brand-new instance over the same file models a process restart.
        await _audit.NewAuditService().AppendAsync("evt_2", "payment.captured", "accepted", new { }, CancellationToken.None);

        var lines = _audit.ReadLines();
        Assert.Equal(Hashes(lines[0]).Hash, Hashes(lines[1]).PrevHash);
        var verification = await PaymentAuditService.VerifyFileAsync(_audit.Path_);
        Assert.Equal(new PaymentChainVerification(true, 2, null), verification);
    }

    [Fact]
    public async Task Append_RefusesToExtendALogWithACorruptedTail()
    {
        await File.WriteAllTextAsync(_audit.Path_, "{ this is not a valid audit line\n");
        var service = _audit.NewAuditService();

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            service.AppendAsync("evt_1", "payment.captured", "accepted", new { }, CancellationToken.None));

        Assert.Single(_audit.ReadLines());
    }

    [Fact]
    public async Task Append_IsSafeUnderConcurrentWriters()
    {
        var service = _audit.NewAuditService();

        await Task.WhenAll(Enumerable.Range(0, 40).Select(i =>
            service.AppendAsync($"evt_{i}", "payment.captured", "accepted", new { i }, CancellationToken.None)));

        var verification = await PaymentAuditService.VerifyFileAsync(_audit.Path_);
        Assert.Equal(new PaymentChainVerification(true, 40, null), verification);
    }

    [Fact]
    public async Task Verify_TreatsAMissingFileAsAnEmptyValidChain()
    {
        var verification = await PaymentAuditService.VerifyFileAsync(_audit.Path_);

        Assert.Equal(new PaymentChainVerification(true, 0, null), verification);
    }

    [Fact]
    public async Task Verify_DetectsAnEditedEntry()
    {
        var service = _audit.NewAuditService();
        for (var i = 0; i < 3; i++)
        {
            await service.AppendAsync($"evt_{i}", "payment.captured", "accepted", new { }, CancellationToken.None);
        }
        var lines = _audit.ReadLines();
        lines[1] = lines[1].Replace("\"state\":\"accepted\"", "\"state\":\"rejected\"");
        await File.WriteAllLinesAsync(_audit.Path_, lines);

        var verification = await PaymentAuditService.VerifyFileAsync(_audit.Path_);

        Assert.False(verification.Valid);
        Assert.Equal(1, verification.BrokenAtIndex);
    }

    [Fact]
    public async Task Verify_DetectsARemovedEntry()
    {
        var service = _audit.NewAuditService();
        for (var i = 0; i < 3; i++)
        {
            await service.AppendAsync($"evt_{i}", "payment.captured", "accepted", new { }, CancellationToken.None);
        }
        var lines = _audit.ReadLines();
        await File.WriteAllLinesAsync(_audit.Path_, [lines[0], lines[2]]);

        var verification = await PaymentAuditService.VerifyFileAsync(_audit.Path_);

        Assert.False(verification.Valid);
        Assert.Equal(1, verification.BrokenAtIndex);
    }

    [Fact]
    public async Task Append_ForwardsTheEventToTheGoBackendWithTheAdminKey()
    {
        var http = StubHttpHandler.Default();
        var service = _audit.NewAuditService(http);

        await service.AppendAsync("evt_fwd", "payment.captured", "accepted", new { paymentId = "pay_1" }, CancellationToken.None);

        var forwarded = await WaitForAsync(() => http.Requests.FirstOrDefault(r => r.Uri.AbsolutePath == "/payment-event"));
        Assert.Equal(GatewayApiService.AdminDemoKey, forwarded.ApiKey);
        using var payload = JsonDocument.Parse(forwarded.Body);
        Assert.Equal("evt_fwd", payload.RootElement.GetProperty("eventId").GetString());
        Assert.Equal("accepted", payload.RootElement.GetProperty("state").GetString());
    }

    [Fact]
    public async Task Append_SucceedsEvenWhenTheGoBackendIsDown()
    {
        var http = new StubHttpHandler(_ => throw new HttpRequestException("backend down"));
        var service = _audit.NewAuditService(http);

        await service.AppendAsync("evt_1", "payment.captured", "accepted", new { }, CancellationToken.None);

        Assert.Single(_audit.ReadLines());
    }

    private static async Task<T> WaitForAsync<T>(Func<T?> probe) where T : class
    {
        for (var attempt = 0; attempt < 100; attempt++)
        {
            if (probe() is { } value)
            {
                return value;
            }
            await Task.Delay(20);
        }
        throw new TimeoutException("condition was not met in time");
    }
}
