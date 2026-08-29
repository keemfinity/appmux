using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace AppMux.Manager;

public sealed class InstanceRow
{
    public required InstanceModel Model { get; init; }
    public string InstanceName => Model.Name;
    public string AppDisplay => Core.FriendlyAppName(Model);
    public ImageSource? Icon { get; init; }
    public bool CanEnableStrongIsolation => Model.Isolation == "recipe";
    public bool IsPackage => Model.Isolation == "package";
    public bool IsStoppable => Model.Isolation is "package" or "web";
    public required string Meta { get; init; }
}

public partial class MainWindow
{
    public MainWindow()
    {
        InitializeComponent();
        SizeChanged += (_, _) => FitInstanceList();
        Loaded += async (_, _) =>
        {
            FitInstanceList();
            ThemeService.ConfigureWindow(this);
            await Core.RunAppmuxAsync("protocol", "sync");
            await RefreshAsync();
        };
    }

    private void FitInstanceList()
    {
        InstanceList.Width = Math.Max(320, ActualWidth - 48);
    }

    private async Task RefreshAsync()
    {
        var instances = Core.LoadInstances()
            .OrderByDescending(i => i.LastUsed)
            .ToList();

        var rows = await Task.Run(() => instances.Select(i =>
        {
            var size = Core.DirSize(Core.InstanceDataDir(i));
            return new InstanceRow
            {
                Model = i,
                Icon = Core.IconForInstance(i),
                Meta = $"{Core.FormatSize(size)}  ·  {i.Isolation switch { "account" => "Private Windows profile", "package" => "Private app profile", "web" => "Private web profile", _ => "Private app profile" }}  ·  Used {Core.FormatAgo(i.LastUsed)}",
            };
        }).ToList());

        InstanceList.ItemsSource = rows;
        EmptyHint.Visibility = rows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private async void OnLaunch(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.Tag is not InstanceRow row) return;
        var (code, output) = await Core.RunAppmuxAsync(
            "run", "--target", row.Model.AppPath,
            "--app", row.Model.AppId,
            "--instance", row.Model.Name);
        if (code != 0)
            await ShowErrorAsync("Launch failed", output);
        await RefreshAsync();
    }

    private async void OnStop(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.Tag is not InstanceRow row || !row.IsStoppable) return;
        var box = new Wpf.Ui.Controls.MessageBox
        {
            Title = $"Stop '{row.Model.Name}'?",
            Content = "This closes every foreground and background process belonging only to " +
                      "this isolated instance. Unsaved work in that instance may be lost. The " +
                      "vendor app and other AppMux instances are not affected.",
            PrimaryButtonText = "Stop instance",
            CloseButtonText = "Cancel",
        };
        if (await box.ShowDialogAsync() != Wpf.Ui.Controls.MessageBoxResult.Primary) return;
        var result = await Core.RunAppmuxAsync(
            "stop", "--app", row.Model.AppId, "--instance", row.Model.Name);
        if (result.Code != 0)
            await ShowErrorAsync("Stop failed", result.Output);
        else
            await RefreshAsync();
    }

    private async void OnDelete(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is not InstanceRow row) return;

        var box = new Wpf.Ui.Controls.MessageBox
        {
            Title = $"Remove '{row.Model.Name}'?",
            Content = row.IsPackage
                ? "AppMux will stop this clone's background processes and uninstall its copied " +
                  "Windows package. The vendor app is not affected.\n\n'Uninstall + wipe profile' " +
                  "also permanently deletes this instance's saved login and settings."
                : $"Remove the {row.AppDisplay} instance '{row.Model.Name}'?\n\n" +
                  "'Remove + wipe data' also deletes its logins and settings permanently.",
            PrimaryButtonText = row.IsPackage ? "Uninstall; keep profile" : "Remove only",
            SecondaryButtonText = row.IsPackage ? "Uninstall + wipe profile" : "Remove + wipe data",
            CloseButtonText = "Cancel",
        };
        var result = await box.ShowDialogAsync();
        if (result == Wpf.Ui.Controls.MessageBoxResult.None) return;

        var args = row.IsPackage
            ? new List<string>
            {
                "package-lab", "uninstall", "--app", row.Model.AppId,
                "--instance", row.Model.Name, "--confirm-uninstall",
            }
            : new List<string> { "remove", "--app", row.Model.AppId, "--instance", row.Model.Name };
        if (result == Wpf.Ui.Controls.MessageBoxResult.Secondary) args.Add("--purge");

        var (code, output) = await Core.RunAppmuxAsync(args.ToArray());
        if (code != 0)
            await ShowErrorAsync("Remove failed", output);
        await RefreshAsync();
    }

    private async void OnStrongIsolation(object sender, RoutedEventArgs e)
    {
        if ((sender as Button)?.Tag is not InstanceRow row) return;
        var confirm = new Wpf.Ui.Controls.MessageBox
        {
            Title = $"Enable strong isolation for '{row.Model.Name}'?",
            Content = "AppMux will ask Windows for administrator approval, create one hidden " +
                      "standard local account for this instance, and pre-warm its profile. " +
                      "That gives the app a real separate HKCU registry and AppData.\n\n" +
                      "No target files, WindowsApps ACLs, services, or drivers are modified. " +
                      "The account receives a random DPAPI-protected password. This instance " +
                      "will start with fresh settings and require login once.",
            PrimaryButtonText = "Continue",
            CloseButtonText = "Cancel",
        };
        if (await confirm.ShowDialogAsync() != Wpf.Ui.Controls.MessageBoxResult.Primary) return;

        var code = await Core.RunElevatedAppmuxAsync(
            "tier-c", "prepare", "--app", row.Model.AppId, "--instance", row.Model.Name);
        if (code == 1223) return;
        if (code != 0)
            await ShowErrorAsync("Strong isolation setup failed", $"Elevated helper exited with code {code}.");
        await RefreshAsync();
    }

    private async void OnShortcut(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.Tag is not InstanceRow row) return;
        var (code, output) = await Core.RunAppmuxAsync(
            "shortcut", "--app", row.Model.AppId, "--instance", row.Model.Name);
        var box = new Wpf.Ui.Controls.MessageBox
        {
            Title = code == 0 ? "Shortcut created" : "Shortcut failed",
            Content = code == 0
                ? $"A '{row.Model.Name}' shortcut is now on your desktop.\n\n" +
                  "Right-click it and choose 'Pin to taskbar' to launch this instance " +
                  "straight from the taskbar."
                : output,
            CloseButtonText = "Close",
        };
        await box.ShowDialogAsync();
    }

    private void OnSettings(object sender, RoutedEventArgs e)
    {
        new SettingsWindow { Owner = this }.ShowDialog();
    }

    private async void OnAddInstance(object sender, RoutedEventArgs e)
    {
        var picker = new AppPickerWindow { Owner = this };
        if (picker.ShowDialog() != true || picker.SelectedPath is null) return;

        var dialog = new NewInstanceWindow(
            picker.SelectedPath,
            standalone: false,
            packageLab: picker.SelectedIsPackaged) { Owner = this };
        dialog.ShowDialog();
        await RefreshAsync();
    }

    private async void OnSyncMenu(object sender, RoutedEventArgs e)
    {
        var (code, output) = await Core.RunAppmuxAsync("menu", "sync");
        if (code != 0)
        {
            await ShowErrorAsync("Menu sync failed", output);
            return;
        }
        var protocol = await Core.RunAppmuxAsync("protocol", "sync");
        if (protocol.Code != 0)
            await ShowErrorAsync("Protocol router sync failed", protocol.Output);
    }

    private static async Task ShowErrorAsync(string title, string detail)
    {
        var box = new Wpf.Ui.Controls.MessageBox
        {
            Title = title,
            Content = string.IsNullOrWhiteSpace(detail) ? "Unknown error." : detail,
            CloseButtonText = "Close",
        };
        await box.ShowDialogAsync();
    }
}
