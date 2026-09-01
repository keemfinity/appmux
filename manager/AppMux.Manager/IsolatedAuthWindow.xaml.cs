using System.Buffers.Binary;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Media.Imaging;
using Microsoft.Web.WebView2.Core;

namespace AppMux.Manager;

public sealed class IsolatedAuthRequest
{
    [JsonPropertyName("url")] public string Url { get; set; } = "";
    [JsonPropertyName("profile")] public string Profile { get; set; } = "";
    [JsonPropertyName("icon")] public string Icon { get; set; } = "";
    [JsonPropertyName("appId")] public string AppId { get; set; } = "";
}

public partial class IsolatedAuthWindow
{
    private readonly string _pipeName;

    public IsolatedAuthWindow(string pipeName)
    {
        InitializeComponent();
        _pipeName = pipeName;
        Loaded += OnLoaded;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        ThemeService.ConfigureWindow(this);
        try
        {
            if (!Regex.IsMatch(_pipeName, @"^AppMux\.AuthRequest\.[A-Za-z0-9_.-]{1,100}\.[a-f0-9]{48}$"))
                throw new InvalidDataException("Invalid authentication pipe name.");
            using var pipe = new NamedPipeClientStream(".", _pipeName, PipeDirection.In, PipeOptions.Asynchronous);
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await pipe.ConnectAsync(timeout.Token);
            var request = JsonSerializer.Deserialize<IsolatedAuthRequest>(await ReadFrameAsync(pipe, timeout.Token))
                ?? throw new InvalidDataException("Authentication request is empty.");
            Validate(request);
            Icon = BitmapFrame.Create(new Uri(request.Icon), BitmapCreateOptions.PreservePixelFormat, BitmapCacheOption.OnLoad);
            var environment = await CoreWebView2Environment.CreateAsync(userDataFolder: request.Profile);
            await Browser.EnsureCoreWebView2Async(environment);
            Browser.CoreWebView2.Navigate(request.Url);
        }
        catch (Exception error)
        {
            MessageBox.Show(error.Message, "AppMux isolated sign in", MessageBoxButton.OK, MessageBoxImage.Error);
            Close();
        }
    }

    private static void Validate(IsolatedAuthRequest request)
    {
        if (!Uri.TryCreate(request.Url, UriKind.Absolute, out var url) || url.Scheme != Uri.UriSchemeHttps)
            throw new InvalidDataException("Authentication URL must use HTTPS.");
        if (!Regex.IsMatch(request.AppId, @"^[A-Za-z0-9_.-]{1,128}$")) throw new InvalidDataException("Invalid application identity.");
        var instances = Path.GetFullPath(Path.Combine(Core.DataRoot, "Instances")) + Path.DirectorySeparatorChar;
        foreach (var path in new[] { request.Profile, request.Icon })
        {
            if (!Path.GetFullPath(path).StartsWith(instances, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Authentication path is outside the AppMux instance root.");
        }
        if (!File.Exists(request.Icon)) throw new FileNotFoundException("Application icon is missing.");
        Directory.CreateDirectory(request.Profile);
    }

    private static async Task<string> ReadFrameAsync(Stream stream, CancellationToken cancellationToken)
    {
        var header = new byte[4];
        await stream.ReadExactlyAsync(header, cancellationToken);
        var length = BinaryPrimitives.ReadUInt32LittleEndian(header);
        if (length == 0 || length > 16384) throw new InvalidDataException("Authentication request is too large.");
        var payload = new byte[length];
        await stream.ReadExactlyAsync(payload, cancellationToken);
        return new UTF8Encoding(false, true).GetString(payload);
    }
}
