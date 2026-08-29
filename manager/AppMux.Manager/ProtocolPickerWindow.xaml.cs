using System.Windows;

namespace AppMux.Manager;

public partial class ProtocolPickerWindow
{
    private readonly string _uri;

    public ProtocolPickerWindow(string uri)
    {
        InitializeComponent();
        _uri = uri;
        Loaded += (_, _) =>
        {
            ThemeService.ConfigureWindow(this);
            LoadInstances();
        };
    }

    private void LoadInstances()
    {
        if (!Uri.TryCreate(_uri, UriKind.Absolute, out var uri))
        {
            SchemeText.Text = "Invalid callback URI.";
            return;
        }
        SchemeText.Text = $"Choose the named instance that requested this {uri.Scheme}:// callback. The sensitive callback URL is not displayed or stored.";
        var instances = Core.LoadInstances()
            .Where(i => i.Isolation == "package" && i.Protocols.Any(p => p.Equals(uri.Scheme, StringComparison.OrdinalIgnoreCase)))
            .OrderByDescending(i => i.LastUsed)
            .ToList();
        InstanceList.ItemsSource = instances;
        if (instances.Count > 0) InstanceList.SelectedIndex = 0;
    }

    private async void OnContinue(object sender, RoutedEventArgs e)
    {
        if (InstanceList.SelectedItem is not InstanceModel instance) return;
        var (code, output) = await Core.RunAppmuxAsync(
            "protocol", "route", "--uri", _uri,
            "--app", instance.AppId, "--instance", instance.Name);
        if (code == 0)
        {
            Close();
            return;
        }
        var box = new Wpf.Ui.Controls.MessageBox
        {
            Title = "Callback routing failed",
            Content = output,
            CloseButtonText = "Close",
        };
        await box.ShowDialogAsync();
    }

    private void OnCancel(object sender, RoutedEventArgs e) => Close();
}
