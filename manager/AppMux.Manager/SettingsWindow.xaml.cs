using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;

namespace AppMux.Manager;

public partial class SettingsWindow
{
    private bool _loading = true;

    public SettingsWindow()
    {
        InitializeComponent();
        Loaded += OnLoaded;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        ThemeService.ConfigureWindow(this);
        var mode = Core.LoadManagerSettings().Theme;
        ThemeBox.SelectedItem = ThemeBox.Items
            .OfType<ComboBoxItem>()
            .FirstOrDefault(item => Equals(item.Tag, mode)) ?? ThemeBox.Items[0];
        DataPathText.Text = Core.DataRoot;
        var dev = await Core.RunAppmuxAsync("dev", "status");
        DevModeCheck.IsChecked = dev.Code == 0 && dev.Output.Contains("ON");
        _loading = false;
    }

    private void OnThemeChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_loading || ThemeBox.SelectedItem is not ComboBoxItem item || item.Tag is not string mode)
            return;
        ThemeService.SetMode(mode);
        StatusText.Text = $"Theme changed to {mode}.";
    }

    private async void OnSyncMenu(object sender, RoutedEventArgs e)
    {
        var result = await Core.RunAppmuxAsync("menu", "sync");
        StatusText.Text = result.Code == 0 ? "Right-click menu synchronized." : result.Output;
    }

    private async void OnSyncProtocols(object sender, RoutedEventArgs e)
    {
        var result = await Core.RunAppmuxAsync("protocol", "sync");
        StatusText.Text = result.Code == 0 ? "Protocol router synchronized." : result.Output;
    }

    private async void OnDeveloperMode(object sender, RoutedEventArgs e)
    {
        if (_loading) return;
        var enabled = DevModeCheck.IsChecked == true;
        var result = await Core.RunAppmuxAsync("dev", enabled ? "on" : "off");
        if (result.Code == 0)
        {
            StatusText.Text = enabled ? "Developer mode enabled." : "Developer mode disabled.";
            return;
        }
        _loading = true;
        DevModeCheck.IsChecked = !enabled;
        _loading = false;
        StatusText.Text = result.Output;
    }

    private void OnOpenData(object sender, RoutedEventArgs e)
    {
        Directory.CreateDirectory(Core.DataRoot);
        Process.Start(new ProcessStartInfo("explorer.exe", Core.DataRoot) { UseShellExecute = true });
    }
}
