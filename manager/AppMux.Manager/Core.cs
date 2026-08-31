using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Xml.Linq;

namespace AppMux.Manager;

public sealed class InstanceModel
{
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("app_id")] public string AppId { get; set; } = "";
    [JsonPropertyName("app_path")] public string AppPath { get; set; } = "";
    [JsonPropertyName("display_name")] public string? DisplayName { get; set; }
    [JsonPropertyName("created")] public ulong Created { get; set; }
    [JsonPropertyName("last_used")] public ulong LastUsed { get; set; }
    [JsonPropertyName("isolation")] public string Isolation { get; set; } = "recipe";
    [JsonPropertyName("windows_user")] public string? WindowsUser { get; set; }
    [JsonPropertyName("tier_d_adapter")] public string? TierDAdapter { get; set; }
    [JsonPropertyName("package_aumid")] public string? PackageAumid { get; set; }
    [JsonPropertyName("protocols")] public List<string> Protocols { get; set; } = new();
    [JsonPropertyName("profile_args")] public List<string> ProfileArgs { get; set; } = new();
    [JsonPropertyName("web_url")] public string? WebUrl { get; set; }
    [JsonIgnore] public string FriendlyName => Core.FriendlyAppName(this);
    [JsonIgnore] public ImageSource IconSource => Core.IconForInstance(this);
}

public sealed class InstanceDb
{
    [JsonPropertyName("instances")] public List<InstanceModel> Instances { get; set; } = new();
}

public sealed class ManagerSettings
{
    [JsonPropertyName("theme")] public string Theme { get; set; } = "System";
}

public sealed class AutoAnalysisModel
{
    [JsonPropertyName("app_id")] public string AppId { get; set; } = "";
    [JsonPropertyName("display")] public string Display { get; set; } = "";
    [JsonPropertyName("route")] public string Route { get; set; } = "unsupported";
    [JsonPropertyName("confidence")] public string Confidence { get; set; } = "";
    [JsonPropertyName("packaged")] public bool Packaged { get; set; }
    [JsonPropertyName("requires_elevation")] public bool RequiresElevation { get; set; }
    [JsonPropertyName("requires_package_consent")] public bool RequiresPackageConsent { get; set; }
    [JsonPropertyName("strip_services")] public bool StripServices { get; set; }
    [JsonPropertyName("web_url")] public string? WebUrl { get; set; }
    [JsonPropertyName("reason")] public string Reason { get; set; } = "";
    [JsonPropertyName("warnings")] public List<string> Warnings { get; set; } = new();
}

/// <summary>Bridge to the Rust core (appmux.exe) and its on-disk state.</summary>
public static class Core
{
    public static string DataRoot =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AppMux");

    public static bool IsTermsAccepted()
    {
        try
        {
            var file = Path.Combine(DataRoot, "config.json");
            if (!File.Exists(file)) return false;
            using var json = JsonDocument.Parse(File.ReadAllText(file));
            return json.RootElement.TryGetProperty("tos_accepted", out var accepted)
                && accepted.ValueKind is JsonValueKind.True;
        }
        catch { return false; }
    }

    public static string FriendlyAppName(InstanceModel instance)
    {
        (string? Name, ImageSource? Icon) packageVisual = instance.Isolation is "package" or "web"
            ? PackageVisual(instance.AppPath)
            : (null, null);
        if (!string.IsNullOrWhiteSpace(packageVisual.Name))
        {
            var suffix = $" ({instance.Name})";
            var packageName = packageVisual.Name.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)
                ? packageVisual.Name[..^suffix.Length]
                : packageVisual.Name;
            return instance.Isolation == "web" ? $"{packageName} Web" : packageName;
        }
        if (!string.IsNullOrWhiteSpace(instance.DisplayName))
        {
            var displayName = instance.DisplayName.EndsWith(".Root", StringComparison.OrdinalIgnoreCase)
                ? instance.DisplayName[..^5]
                : instance.DisplayName;
            return instance.Isolation == "web" ? $"{displayName} Web" : displayName;
        }
        try
        {
            if (Path.GetExtension(instance.AppPath).Equals(".exe", StringComparison.OrdinalIgnoreCase))
            {
                var version = FileVersionInfo.GetVersionInfo(instance.AppPath);
                var product = version.ProductName?.Trim();
                if (!string.IsNullOrWhiteSpace(product))
                {
                    if (product.EndsWith(".Root", StringComparison.OrdinalIgnoreCase)) product = product[..^5];
                    return instance.Isolation == "web" ? $"{product} Web" : product;
                }
                var description = version.FileDescription?.Trim();
                if (!string.IsNullOrWhiteSpace(description))
                    return instance.Isolation == "web" ? $"{description} Web" : description;
            }
        }
        catch { }
        var id = instance.AppId
            .Replace("package-", "", StringComparison.OrdinalIgnoreCase)
            .Replace("web-", "", StringComparison.OrdinalIgnoreCase)
            .Replace('_', ' ')
            .Replace('-', ' ');
        var friendly = string.Join(" ", id.Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .Select(part => char.ToUpperInvariant(part[0]) + part[1..]));
        return instance.Isolation == "web" ? $"{friendly} Web" : friendly;
    }

    public static ImageSource IconForInstance(InstanceModel instance)
    {
        return IconForPath(instance.AppPath) ?? AppMuxFallbackIcon();
    }

    public static ImageSource? IconForPath(string path)
    {
        var resolved = ResolveShortcutTarget(path);
        return PackageVisual(resolved).Icon ?? ExtractIcon(resolved);
    }

    private static string ResolveShortcutTarget(string path)
    {
        if (!Path.GetExtension(path).Equals(".lnk", StringComparison.OrdinalIgnoreCase)) return path;
        object? shell = null;
        object? shortcut = null;
        try
        {
            var type = Type.GetTypeFromProgID("WScript.Shell");
            if (type is null) return path;
            shell = Activator.CreateInstance(type);
            if (shell is null) return path;
            shortcut = shell.GetType().InvokeMember(
                "CreateShortcut",
                System.Reflection.BindingFlags.InvokeMethod,
                null,
                shell,
                new object[] { path });
            var iconLocation = shortcut?.GetType().InvokeMember(
                "IconLocation",
                System.Reflection.BindingFlags.GetProperty,
                null,
                shortcut,
                null) as string;
            var iconPath = iconLocation?.Split(',')[0].Trim().Trim('"');
            if (!string.IsNullOrWhiteSpace(iconPath))
            {
                iconPath = Environment.ExpandEnvironmentVariables(iconPath);
                if (File.Exists(iconPath)) return iconPath;
            }
            var target = shortcut?.GetType().InvokeMember(
                "TargetPath",
                System.Reflection.BindingFlags.GetProperty,
                null,
                shortcut,
                null) as string;
            return string.IsNullOrWhiteSpace(target) ? path : target;
        }
        catch { return path; }
        finally
        {
            if (shortcut is not null && Marshal.IsComObject(shortcut)) Marshal.FinalReleaseComObject(shortcut);
            if (shell is not null && Marshal.IsComObject(shell)) Marshal.FinalReleaseComObject(shell);
        }
    }

    private static (string? Name, ImageSource? Icon) PackageVisual(string executable)
    {
        try
        {
            var directory = new FileInfo(executable).Directory;
            while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "AppxManifest.xml")))
                directory = directory.Parent;
            if (directory is null) return (null, null);
            var manifest = XDocument.Load(Path.Combine(directory.FullName, "AppxManifest.xml"));
            var relative = Path.GetRelativePath(directory.FullName, executable).Replace('/', '\\');
            var applications = manifest.Descendants()
                .Where(node => node.Name.LocalName == "Application")
                .ToList();
            var application = applications.FirstOrDefault(node =>
                string.Equals(node.Attribute("Executable")?.Value.Replace('/', '\\'), relative,
                    StringComparison.OrdinalIgnoreCase)) ?? applications.FirstOrDefault();
            var visual = application?.Descendants()
                .FirstOrDefault(node => node.Name.LocalName == "VisualElements");
            var name = visual?.Attribute("DisplayName")?.Value;
            if (name?.StartsWith("ms-resource:", StringComparison.OrdinalIgnoreCase) == true) name = null;
            var logo = visual?.Attribute("Square44x44Logo")?.Value.Replace('/', '\\');
            if (string.IsNullOrWhiteSpace(logo)) return (name, null);
            var direct = Path.Combine(directory.FullName, logo);
            var iconPath = File.Exists(direct) ? direct : FindQualifiedLogo(direct);
            return (name, iconPath is null ? null : LoadImage(iconPath));
        }
        catch { return (null, null); }
    }

    private static string? FindQualifiedLogo(string declaredPath)
    {
        var directory = Path.GetDirectoryName(declaredPath);
        var stem = Path.GetFileNameWithoutExtension(declaredPath);
        if (directory is null || !Directory.Exists(directory)) return null;
        var files = Directory.EnumerateFiles(directory, $"{stem}*.png").ToList();
        return files.FirstOrDefault(file => file.Contains("targetsize-48", StringComparison.OrdinalIgnoreCase))
            ?? files.FirstOrDefault(file => file.Contains("targetsize-64", StringComparison.OrdinalIgnoreCase))
            ?? files.FirstOrDefault(file => file.Contains("scale-200", StringComparison.OrdinalIgnoreCase))
            ?? files.FirstOrDefault();
    }

    private static ImageSource LoadImage(string path)
    {
        var image = new BitmapImage();
        image.BeginInit();
        image.CacheOption = BitmapCacheOption.OnLoad;
        image.DecodePixelWidth = 96;
        image.UriSource = new Uri(path, UriKind.Absolute);
        image.EndInit();
        image.Freeze();
        return image;
    }

    private static ImageSource AppMuxFallbackIcon()
    {
        var image = new BitmapImage();
        image.BeginInit();
        image.CacheOption = BitmapCacheOption.OnLoad;
        image.UriSource = new Uri("pack://application:,,,/Assets/AppMux.png", UriKind.Absolute);
        image.EndInit();
        image.Freeze();
        return image;
    }

    public static ImageSource? ExtractIcon(string path)
    {
        var info = new SHFILEINFO();
        var result = SHGetFileInfo(path, 0, ref info, (uint)Marshal.SizeOf<SHFILEINFO>(),
            SHGFI_ICON | SHGFI_LARGEICON);
        if (result == IntPtr.Zero || info.hIcon == IntPtr.Zero) return null;
        try
        {
            var source = Imaging.CreateBitmapSourceFromHIcon(
                info.hIcon, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
            source.Freeze();
            return source;
        }
        catch { return null; }
        finally { DestroyIcon(info.hIcon); }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SHFILEINFO
    {
        public IntPtr hIcon;
        public int iIcon;
        public uint dwAttributes;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szDisplayName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 80)] public string szTypeName;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr SHGetFileInfo(
        string pszPath, uint dwFileAttributes, ref SHFILEINFO psfi, uint cbFileInfo, uint uFlags);

    [DllImport("user32.dll")]
    private static extern bool DestroyIcon(IntPtr hIcon);

    private const uint SHGFI_ICON = 0x100;
    private const uint SHGFI_LARGEICON = 0x0;

    public static string InstanceDataDir(InstanceModel i) =>
        Path.Combine(DataRoot, "Instances", Sanitize(i.AppId), Sanitize(i.Name));

    public static ManagerSettings LoadManagerSettings()
    {
        try
        {
            var file = Path.Combine(DataRoot, "manager.json");
            return File.Exists(file)
                ? JsonSerializer.Deserialize<ManagerSettings>(File.ReadAllText(file)) ?? new()
                : new();
        }
        catch { return new(); }
    }

    public static void SaveManagerSettings(ManagerSettings settings)
    {
        Directory.CreateDirectory(DataRoot);
        var file = Path.Combine(DataRoot, "manager.json");
        var temporary = file + ".tmp";
        File.WriteAllText(temporary, JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true }));
        File.Move(temporary, file, true);
    }

    public static List<InstanceModel> LoadInstances()
    {
        var file = Path.Combine(DataRoot, "instances.json");
        if (!File.Exists(file)) return new List<InstanceModel>();
        var db = JsonSerializer.Deserialize<InstanceDb>(File.ReadAllText(file));
        return db?.Instances ?? new List<InstanceModel>();
    }

    /// <summary>Locate appmux.exe: next to the manager, or the dev target dir.</summary>
    public static string? FindAppmux()
    {
        var local = Path.Combine(AppContext.BaseDirectory, "appmux.exe");
        if (File.Exists(local)) return local;

        // Dev fallback: walk up from bin/... to the repo root (has Cargo.toml).
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "Cargo.toml")))
            {
                var dev = Path.Combine(dir.FullName, "target", "release", "appmux.exe");
                if (File.Exists(dev)) return dev;
            }
            dir = dir.Parent;
        }
        return null;
    }

    /// <summary>Run appmux.exe hidden; returns (exitCode, stdout+stderr).</summary>
    public static async Task<AutoAnalysisModel> AnalyzeAsync(string target)
    {
        var (code, output) = await RunAppmuxAsync("analyze", "--target", target);
        if (code != 0) throw new InvalidOperationException(output);
        return JsonSerializer.Deserialize<AutoAnalysisModel>(output)
            ?? throw new InvalidDataException("AppMux returned an empty route analysis.");
    }

    public static async Task<int> RunElevatedAppmuxAsync(params string[] args)
    {
        var console = FindAppmux() ?? throw new FileNotFoundException("appmux.exe not found.");
        var windowless = Path.Combine(Path.GetDirectoryName(console)!, "appmuxw.exe");
        var exe = File.Exists(windowless) ? windowless : console;
        var psi = new ProcessStartInfo(exe)
        {
            UseShellExecute = true,
            Verb = "runas",
            WindowStyle = ProcessWindowStyle.Hidden,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        try
        {
            using var p = Process.Start(psi)!;
            await p.WaitForExitAsync();
            return p.ExitCode;
        }
        catch (System.ComponentModel.Win32Exception e) when (e.NativeErrorCode == 1223)
        {
            return 1223; // UAC cancelled
        }
    }

    public static async Task<(int Code, string Output)> RunAppmuxAsync(params string[] args)
    {
        var exe = FindAppmux() ?? throw new FileNotFoundException(
            "appmux.exe not found next to the manager or in target\\release.");
        var psi = new ProcessStartInfo(exe)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        var stdoutTask = p.StandardOutput.ReadToEndAsync();
        var stderrTask = p.StandardError.ReadToEndAsync();
        await Task.WhenAll(stdoutTask, stderrTask, p.WaitForExitAsync());
        return (p.ExitCode, (stdoutTask.Result + "\n" + stderrTask.Result).Trim());
    }

    public static bool IsPackageLabCertificateMachineTrusted()
    {
        try
        {
            using var store = new X509Store(StoreName.TrustedPeople, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly);
            return store.Certificates.Any(c => c.Subject == "CN=AppMux Package Lab" && c.NotAfter > DateTime.Now);
        }
        catch { return false; }
    }

    public static long DirSize(string path)
    {
        try
        {
            if (!Directory.Exists(path)) return 0;
            return new DirectoryInfo(path)
                .EnumerateFiles("*", SearchOption.AllDirectories)
                .Sum(f => { try { return f.Length; } catch { return 0L; } });
        }
        catch { return 0; }
    }

    public static string FormatSize(long bytes) => bytes switch
    {
        >= 1L << 30 => $"{bytes / (double)(1L << 30):0.0} GB",
        >= 1L << 20 => $"{bytes / (double)(1L << 20):0.0} MB",
        >= 1L << 10 => $"{bytes / (double)(1L << 10):0.0} KB",
        _ => $"{bytes} B",
    };

    public static string FormatAgo(ulong unixSeconds)
    {
        if (unixSeconds == 0) return "never";
        var then = DateTimeOffset.FromUnixTimeSeconds((long)unixSeconds);
        var span = DateTimeOffset.UtcNow - then;
        return span.TotalDays >= 2 ? $"{(int)span.TotalDays} days ago"
            : span.TotalDays >= 1 ? "yesterday"
            : span.TotalHours >= 1 ? $"{(int)span.TotalHours} h ago"
            : span.TotalMinutes >= 1 ? $"{(int)span.TotalMinutes} min ago"
            : "just now";
    }

    /// <summary>Mirror of the Rust paths::sanitize.</summary>
    private static string Sanitize(string s)
    {
        var trimmed = s.Trim();
        var chars = trimmed.Select(c =>
            char.IsLetterOrDigit(c) || c is '-' or '_' ? char.ToLowerInvariant(c)
            : c == ' ' ? '-'
            : '_');
        var result = new string(chars.ToArray());
        return result.Length == 0 ? "app" : result;
    }
}
