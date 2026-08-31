using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Microsoft.Win32;

namespace AppMux.Manager;

public sealed class AppEntry
{
    public required string Name { get; init; }
    public required string Path { get; init; }
    public required string Location { get; init; }
    public ImageSource? Icon { get; init; }
    public bool Unsupported { get; init; }
    public double RowOpacity => Unsupported ? 0.7 : 1.0;
}

public partial class AppPickerWindow
{
    /// <summary>Set when the user picked something; null if cancelled.</summary>
    public string? SelectedPath { get; private set; }
    public bool SelectedIsPackaged { get; private set; }

    private List<AppEntry> _startMenu = new();
    private List<AppEntry> _running = new();
    private List<AppEntry> _processes = new();

    private static readonly string[] ExcludedWords =
        { "uninstall", "readme", "help", "website", "documentation", "release notes" };

    /// <summary>Shell hosts and system processes that make no sense to instance.</summary>
    private static readonly string[] ExcludedProcesses =
    {
        "explorer", "applicationframehost", "textinputhost", "systemsettings",
        "shellexperiencehost", "startmenuexperiencehost", "searchhost", "taskmgr",
        "appmux.manager",
    };

    public AppPickerWindow()
    {
        InitializeComponent();
        Loaded += async (_, _) =>
        {
            ThemeService.ConfigureWindow(this);
            SearchBox.Focus();
            _startMenu = await Task.Run(ScanClassicStartMenu);
            ApplyFilter();
            var packaged = await Task.Run(ScanPackagedApps);
            _startMenu = MergeApps(_startMenu, packaged);
            ApplyFilter();
        };
        AppList.SelectionChanged += (_, _) => SelectButton.IsEnabled = AppList.SelectedItem is not null;
    }

    private async void OnSourceChanged(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return;
        if (RunningRadio.IsChecked == true)
        {
            // Rescan every switch so the list reflects what's open right now.
            _running = await Task.Run(() => ScanProcesses(windowedOnly: true));
        }
        else if (ProcessesRadio.IsChecked == true)
        {
            _processes = await Task.Run(() => ScanProcesses(windowedOnly: false));
        }
        ApplyFilter();
    }

    /// <param name="windowedOnly">
    /// true: only processes with a visible main window ("Running now").
    /// false: every process we can resolve a path for, minus Windows system
    /// binaries. "All processes" includes tray and background apps.
    /// </param>
    private static List<AppEntry> ScanProcesses(bool windowedOnly)
    {
        var windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var seen = new Dictionary<string, AppEntry>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in System.Diagnostics.Process.GetProcesses())
        {
            try
            {
                if (windowedOnly && p.MainWindowHandle == IntPtr.Zero) continue;
                if (ExcludedProcesses.Contains(p.ProcessName.ToLowerInvariant())) continue;
                // Works for elevated processes too (unlike Process.MainModule).
                var path = GetProcessPath(p.Id);
                if (path is null) continue;
                if (!windowedOnly && path.StartsWith(windowsDir, StringComparison.OrdinalIgnoreCase)) continue;
                if (seen.ContainsKey(path)) continue;
                // Store/UWP apps can't be instanced (OS-managed package
                // identity); show them greyed out instead of hiding them.
                var isStore = path.Contains(@"\WindowsApps\", StringComparison.OrdinalIgnoreCase);
                var title = p.MainWindowTitle;
                var name = windowedOnly && !string.IsNullOrWhiteSpace(title) && title.Length <= 60
                    ? title
                    : p.ProcessName;
                seen[path] = new AppEntry
                {
                    Name = name,
                    Path = path,
                    Location = isStore ? "Microsoft Store app (experimental Package Lab)" : path,
                    Icon = Core.IconForPath(path),
                    Unsupported = isStore,
                };
            }
            catch
            {
                // Inaccessible process: skip.
            }
        }
        return seen.Values.OrderBy(e => e.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    // ---- process path (works across elevation) ----------------------------

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool QueryFullProcessImageName(
        IntPtr hProcess, uint flags, char[] buffer, ref uint size);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    private static string? GetProcessPath(int pid)
    {
        var handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (handle == IntPtr.Zero) return null;
        try
        {
            var buffer = new char[1024];
            var size = (uint)buffer.Length;
            return QueryFullProcessImageName(handle, 0, buffer, ref size)
                ? new string(buffer, 0, (int)size)
                : null;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    private static List<AppEntry> ScanClassicStartMenu()
    {
        var roots = new[]
        {
            (Environment.GetFolderPath(Environment.SpecialFolder.Programs), "Start Menu (you)"),
            (Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms), "Start Menu (all users)"),
        };

        var seen = new Dictionary<string, AppEntry>(StringComparer.OrdinalIgnoreCase);
        foreach (var (root, location) in roots)
        {
            if (!Directory.Exists(root)) continue;
            foreach (var lnk in Directory.EnumerateFiles(root, "*.lnk", SearchOption.AllDirectories))
            {
                var name = Path.GetFileNameWithoutExtension(lnk);
                var lower = name.ToLowerInvariant();
                if (ExcludedWords.Any(w => lower.Contains(w))) continue;
                if (seen.ContainsKey(name)) continue; // user copy wins (enumerated first)
                seen[name] = new AppEntry
                {
                    Name = name,
                    Path = lnk,
                    Location = location,
                    Icon = Core.IconForPath(lnk),
                };
            }
        }
        return seen.Values.OrderBy(e => e.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private sealed class PackagedAppRecord
    {
        public string Name { get; init; } = "";
        public string Path { get; init; } = "";
    }

    private static List<AppEntry> ScanPackagedApps()
    {
        const string script = """
            $ErrorActionPreference = 'SilentlyContinue'
            [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
            $startNames = @{}
            Get-StartApps | ForEach-Object { $startNames[$_.AppID] = $_.Name }
            $result = @()
            Get-AppxPackage | Where-Object Publisher -ne 'CN=AppMux Package Lab' | ForEach-Object {
              $package = $_
              try {
                $manifest = Get-AppxPackageManifest -Package $package.PackageFullName
                foreach ($app in @($manifest.Package.Applications.Application)) {
                  if (-not $app.Id -or -not $app.Executable) { continue }
                  $aumid = "$($package.PackageFamilyName)!$($app.Id)"
                  $path = Join-Path $package.InstallLocation ([string]$app.Executable)
                  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
                  $name = $startNames[$aumid]
                  if (-not $name) { $name = [string]$app.VisualElements.DisplayName }
                  if (-not $name -or $name -like 'ms-resource:*') { $name = $package.Name }
                  $result += [PSCustomObject]@{ Name = $name; Path = $path }
                }
              } catch {}
            }
            ConvertTo-Json -InputObject @($result) -Compress
            """;

        try
        {
            var start = new System.Diagnostics.ProcessStartInfo("powershell.exe")
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };
            start.ArgumentList.Add("-NoProfile");
            start.ArgumentList.Add("-NonInteractive");
            start.ArgumentList.Add("-Command");
            start.ArgumentList.Add(script);
            using var process = System.Diagnostics.Process.Start(start)!;
            var json = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            if (process.ExitCode != 0 || string.IsNullOrWhiteSpace(json)) return new();
            var records = JsonSerializer.Deserialize<List<PackagedAppRecord>>(
                json,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? new();
            return records
                .Where(r => !string.IsNullOrWhiteSpace(r.Name) && File.Exists(r.Path))
                .GroupBy(r => r.Path, StringComparer.OrdinalIgnoreCase)
                .Select(g => g.First())
                .Select(r => new AppEntry
                {
                    Name = r.Name,
                    Path = r.Path,
                    Location = "Microsoft Store app (experimental Package Lab)",
                    Icon = Core.IconForPath(r.Path),
                    Unsupported = true,
                })
                .OrderBy(e => e.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
        catch
        {
            return new();
        }
    }

    private static List<AppEntry> MergeApps(IEnumerable<AppEntry> classic, IEnumerable<AppEntry> packaged)
    {
        var merged = new Dictionary<string, AppEntry>(StringComparer.OrdinalIgnoreCase);
        foreach (var app in classic) merged.TryAdd(app.Name, app);
        foreach (var app in packaged) merged.TryAdd(app.Name, app);
        return merged.Values.OrderBy(e => e.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private void ApplyFilter()
    {
        var source = RunningRadio.IsChecked == true ? _running
            : ProcessesRadio.IsChecked == true ? _processes
            : _startMenu;
        var q = SearchBox.Text.Trim();
        AppList.ItemsSource = q.Length == 0
            ? source
            : source.Where(e => e.Name.Contains(q, StringComparison.OrdinalIgnoreCase)).ToList();
    }

    private void OnSearchChanged(object sender, TextChangedEventArgs e) => ApplyFilter();

    private void OnItemDoubleClick(object sender, RoutedEventArgs e) => OnSelect(sender, e);

    private void OnSelect(object sender, RoutedEventArgs e)
    {
        if (AppList.SelectedItem is not AppEntry entry) return;
        SelectedIsPackaged = entry.Unsupported;
        SelectedPath = entry.Path;
        DialogResult = true;
    }

    private void OnBrowse(object sender, RoutedEventArgs e)
    {
        var picker = new OpenFileDialog
        {
            Title = "Choose a program or shortcut",
            Filter = "Programs and shortcuts (*.exe;*.lnk)|*.exe;*.lnk",
        };
        if (picker.ShowDialog(this) != true) return;
        SelectedPath = picker.FileName;
        DialogResult = true;
    }

    private void OnCancel(object sender, RoutedEventArgs e) => DialogResult = false;

}
