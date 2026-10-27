using System.Diagnostics;

namespace Sentinel.Agent;

public static class AgentInstaller
{
    private const string TaskName = "SENTINEL-Agent";

    public static int Install()
    {
        var exePath = Environment.ProcessPath;
        if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath))
        {
            Console.WriteLine("ERROR: could not resolve the agent executable path.");
            return 1;
        }

        var result = RunSchtasks("/create",
            "/tn", TaskName,
            "/tr", $"\"{exePath}\" --run-agent",
            "/sc", "onlogon",
            "/delay", "0000:30",
            "/rl", "LIMITED",
            "/f");

        if (result.ExitCode != 0)
        {
            ReportFailure("create", result);
            return result.ExitCode;
        }

        Console.WriteLine("Agent will start automatically at logon.");
        Console.WriteLine($"  Task: {TaskName}");
        Console.WriteLine($"  Exe:  {exePath}");
        return 0;
    }

    public static int Uninstall()
    {
        if (!IsInstalled())
        {
            Console.WriteLine($"Logon task '{TaskName}' is not installed; nothing to remove.");
            return 0;
        }

        var result = RunSchtasks("/delete", "/tn", TaskName, "/f");
        if (result.ExitCode != 0)
        {
            ReportFailure("delete", result);
            return result.ExitCode;
        }

        if (IsInstalled())
        {
            Console.WriteLine("ERROR: task still present after delete.");
            return 1;
        }

        Console.WriteLine("Logon task removed.");
        return 0;
    }

    public static int Status()
    {
        var result = RunSchtasks("/query", "/tn", TaskName, "/fo", "LIST", "/v");
        if (result.ExitCode != 0)
        {
            Console.WriteLine($"Logon task '{TaskName}' is not installed.");
            return 0;
        }

        if (!string.IsNullOrWhiteSpace(result.Output))
            Console.WriteLine(result.Output);
        return 0;
    }

    private static bool IsInstalled() =>
        RunSchtasks("/query", "/tn", TaskName).ExitCode == 0;

    private static void ReportFailure(string action, (int ExitCode, string Output) result)
    {
        Console.WriteLine($"schtasks {action} failed (exit {result.ExitCode}).");
        if (!string.IsNullOrWhiteSpace(result.Output))
            Console.WriteLine(result.Output);
        Console.WriteLine("Hint: run from an elevated prompt if the task cannot be created or removed.");
    }

    private static (int ExitCode, string Output) RunSchtasks(params string[] arguments)
    {
        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = "schtasks.exe",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            foreach (var argument in arguments)
                startInfo.ArgumentList.Add(argument);

            using var process = Process.Start(startInfo);
            if (process is null)
                return (-1, "ERROR: could not start schtasks.exe.");

            var stdout = process.StandardOutput.ReadToEndAsync();
            var stderr = process.StandardError.ReadToEndAsync();

            if (!process.WaitForExit(15_000))
            {
                try { process.Kill(entireProcessTree: true); } catch { }
                return (-1, "ERROR: schtasks timed out after 15 seconds.");
            }

            var output = string.Join(Environment.NewLine,
                new[] { stdout.GetAwaiter().GetResult(), stderr.GetAwaiter().GetResult() }
                    .Where(part => !string.IsNullOrWhiteSpace(part))
                    .Select(part => part.Trim()));

            return (process.ExitCode, output);
        }
        catch (Exception ex)
        {
            return (-1, $"ERROR: {ex.Message}");
        }
    }
}
