using System.Buffers.Binary;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace AppMux.Manager;

public sealed class WaitingCallback
{
    [JsonPropertyName("pipeName")] public string PipeName { get; set; } = "";
    [JsonPropertyName("protocol")] public string Protocol { get; set; } = "";
    [JsonPropertyName("created")] public long Created { get; set; }
}

public static class PackagedCallbackBroker
{
    public static async Task RouteAsync(Uri callback)
    {
        var value = callback.OriginalString;
        if (callback.Scheme != "figma" || value.Length <= 6 || Encoding.UTF8.GetByteCount(value) > 8192
            || value.Any(character => char.IsControl(character)))
            throw new InvalidDataException("Unsupported protocol activation.");
        var directory = Path.Combine(Core.DataRoot, "AuthWaiting");
        if (!Directory.Exists(directory)) throw new InvalidOperationException("No AppMux instance is waiting for authentication.");
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var candidates = Directory.GetFiles(directory, "*.json")
            .Select(path => (Path: path, Value: Read(path)))
            .Where(item => item.Value is not null && item.Value.Protocol == callback.Scheme
                && now - item.Value.Created is >= 0 and <= 300000
                && Regex.IsMatch(item.Value.PipeName, @"^AppMux\.Callback\.[A-Za-z0-9_.-]{1,100}\.[a-f0-9]{48}$"))
            .OrderByDescending(item => item.Value!.Created)
            .ToList();
        if (candidates.Count != 1) throw new InvalidOperationException("Authentication requires exactly one waiting AppMux instance.");
        var selected = candidates[0];
        try
        {
            using var pipe = new NamedPipeClientStream(".", selected.Value!.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await pipe.ConnectAsync(timeout.Token);
            var payload = Encoding.UTF8.GetBytes(value);
            var header = new byte[4];
            BinaryPrimitives.WriteUInt32LittleEndian(header, (uint)payload.Length);
            await pipe.WriteAsync(header, timeout.Token);
            await pipe.WriteAsync(payload, timeout.Token);
            await pipe.FlushAsync(timeout.Token);
            var response = new byte[2];
            await pipe.ReadExactlyAsync(response, timeout.Token);
            if (Encoding.ASCII.GetString(response) != "ok") throw new IOException("The running instance rejected the callback.");
        }
        finally
        {
            File.Delete(selected.Path);
        }
    }

    private static WaitingCallback? Read(string path)
    {
        try { return JsonSerializer.Deserialize<WaitingCallback>(File.ReadAllText(path)); }
        catch { return null; }
    }
}
