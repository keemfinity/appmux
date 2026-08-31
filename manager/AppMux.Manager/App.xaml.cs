using System.Windows;

namespace AppMux.Manager;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        ThemeService.ApplySaved();

        // Never die silently: surface unexpected errors instead of closing.
        DispatcherUnhandledException += (_, args) =>
        {
            args.Handled = true;
            MessageBox.Show(
                args.Exception.ToString(),
                "AppMux: unexpected error",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        };

        // "AppMux.Manager.exe new-instance --target <path>" opens only the
        // naming dialog (used by the Explorer context menu), then exits.
        var args = e.Args;
        if (args.Length >= 3 && args[0] == "protocol" && args[1] == "--uri")
        {
            new ProtocolPickerWindow(args[2]).Show();
            return;
        }
        if (args.Length >= 3 && args[0] == "new-instance" && args[1] == "--target")
        {
            var dialog = new NewInstanceWindow(args[2], standalone: true);
            dialog.Show();
            return;
        }

        new MainWindow().Show();
    }
}
