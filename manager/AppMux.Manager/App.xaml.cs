using System.Windows;

namespace AppMux.Manager;

public partial class App : Application
{
    private static Uri? GetPackagedProtocolActivation()
    {
        try
        {
            var activation = global::Windows.ApplicationModel.AppInstance.GetActivatedEventArgs();
            return activation?.Kind == global::Windows.ApplicationModel.Activation.ActivationKind.Protocol
                && activation is global::Windows.ApplicationModel.Activation.ProtocolActivatedEventArgs protocol
                    ? protocol.Uri : null;
        }
        catch
        {
            return null;
        }
    }

    private async void RoutePackagedProtocol(Uri callback)
    {
        try
        {
            await PackagedCallbackBroker.RouteAsync(callback);
        }
        catch (Exception error)
        {
            MessageBox.Show(error.Message, "AppMux callback broker", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        Shutdown();
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        var packagedProtocol = GetPackagedProtocolActivation();
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
        if (packagedProtocol is not null)
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            RoutePackagedProtocol(packagedProtocol);
            return;
        }

        var args = e.Args;
        if (args.Length >= 3 && args[0] == "isolated-auth" && args[1] == "--pipe")
        {
            new IsolatedAuthWindow(args[2]).Show();
            return;
        }
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
