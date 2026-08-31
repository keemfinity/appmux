using System.IO;
using System.Windows;
using System.Windows.Input;

namespace AppMux.Manager;

public partial class NewInstanceWindow
{
    private readonly string _target;
    private readonly bool _standalone;
    private bool _packageLab;
    private bool _busy;
    private string _defaultCreateText = "Create and launch";
    private AutoAnalysisModel? _analysis;

    public NewInstanceWindow(string target, bool standalone, bool packageLab = false)
    {
        InitializeComponent();
        _target = target;
        _standalone = standalone;
        _packageLab = packageLab;
        TargetText.Text = packageLab
            ? $"{Path.GetFileName(target)} · Experimental Package Lab"
            : Path.GetFileName(target);
        if (packageLab)
        {
            _defaultCreateText = "Build and install test instance";
            CreateButton.Content = _defaultCreateText;
            ErrorText.Text = "This copies and repackages the app locally; it may take several minutes.";
            ErrorText.Visibility = Visibility.Visible;
        }
        Loaded += async (_, _) =>
        {
            ThemeService.ConfigureWindow(this);
            NameBox.Focus();
            try
            {
                _analysis = await Core.AnalyzeAsync(_target);
                _packageLab = _analysis.Route.StartsWith("package-lab");
                RouteText.Text = $"Auto route: {_analysis.Route switch
                {
                    "recipe-a" => "native app profile flags",
                    "recipe-b" => "verified environment profile",
                    "tier-c" => "strong Windows-user isolation (UAC)",
                    "tier-d" => "version-gated Compatibility Shim (UAC)",
                    "web-app" => "isolated official web app",
                    "package-lab" => "separate signed package identity",
                    "package-lab-service-free" => "service-free package identity",
                    _ => "unsupported",
                }} · {_analysis.Confidence}";
                if (_analysis.Route == "unsupported")
                {
                    CreateButton.IsEnabled = false;
                    ShowError(_analysis.Reason);
                }
                else
                {
                    CreateButton.IsEnabled = true;
                    if (_packageLab)
                    {
                        _defaultCreateText = "Build and install test instance";
                        CreateButton.Content = _defaultCreateText;
                    }
                }
            }
            catch (Exception error)
            {
                CreateButton.IsEnabled = false;
                RouteText.Text = "Auto route: analysis failed";
                ShowError(error.Message);
            }
        };
        Closed += (_, _) =>
        {
            if (_standalone) Application.Current.Shutdown();
        };
    }

    private void OnNameKeyDown(object sender, KeyEventArgs e)
    {
        if (_busy) return;
        if (e.Key == Key.Enter) OnCreate(sender, e);
        if (e.Key == Key.Escape) Close();
    }

    private void OnCancel(object sender, RoutedEventArgs e)
    {
        if (!_busy) Close();
    }

    private async void OnCreate(object sender, RoutedEventArgs e)
    {
        if (_busy) return;
        var name = NameBox.Text.Trim();
        if (!IsValidName(name))
        {
            ShowError("Use 1-32 characters containing letters, digits, spaces, hyphens, underscores, or periods.");
            return;
        }
        try
        {
            await CreateInstance(name);
        }
        catch (Exception error)
        {
            FailProgress(error.Message);
        }
    }

    private async Task CreateInstance(string name)
    {
        if (!Core.IsTermsAccepted())
        {
            var notice = new Wpf.Ui.Controls.MessageBox
            {
                Title = "Before creating an instance",
                Content = "AppMux runs multiple copies of a program with separate settings. " +
                          "Running multiple copies may breach that program's own terms of service. " +
                          "Checking whether that is allowed is your responsibility.",
                PrimaryButtonText = "I understand and continue",
                CloseButtonText = "Cancel",
            };
            if (await notice.ShowDialogAsync() != Wpf.Ui.Controls.MessageBoxResult.Primary) return;
            var accepted = await Core.RunAppmuxAsync("accept-tos");
            if (accepted.Code != 0)
            {
                ShowError(string.IsNullOrWhiteSpace(accepted.Output)
                    ? "Unable to save terms acceptance."
                    : accepted.Output);
                return;
            }
        }

        if (_analysis?.Route == "web-app")
        {
            await CreateWebInstance(name);
            return;
        }
        if (_analysis?.Route is "tier-c" or "tier-d")
        {
            await CreateTierCInstance(name);
            return;
        }
        if (_packageLab)
        {
            await CreatePackageLabInstance(name);
            return;
        }

        BeginProgress("Creating the instance...", 25);
        var (code, output) = await Core.RunAppmuxLaunchAsync(
            "run", "--target", _target, "--instance", name);
        if (code != 0)
        {
            FailProgress(string.IsNullOrWhiteSpace(output) ? "Launch failed." : output);
            return;
        }
        await CompleteProgress();
    }

    private async Task CreateWebInstance(string name)
    {
        if (_analysis?.WebUrl is null) return;
        var confirm = new Wpf.Ui.Controls.MessageBox
        {
            Title = "Use isolated App Web mode?",
            Content = $"The desktop package cannot be safely isolated under AppMux's rules. " +
                      $"AppMux will open the verified official site {_analysis.WebUrl} in a " +
                      "dedicated Edge/Chrome app window with its own persistent cookies and login.\n\n" +
                      "It runs side by side without modifying the licensed desktop app. " +
                      "Native-only desktop features are unavailable.",
            PrimaryButtonText = "Create App Web instance",
            CloseButtonText = "Cancel",
        };
        if (await confirm.ShowDialogAsync() != Wpf.Ui.Controls.MessageBoxResult.Primary)
        {
            CreateButton.IsEnabled = true;
            return;
        }
        BeginProgress("Opening the isolated web app...", 45);
        var result = await Core.RunAppmuxLaunchAsync(
            "web", "create", "--target", _target, "--instance", name);
        if (result.Code != 0)
        {
            FailProgress(result.Output);
            return;
        }
        await CompleteProgress();
    }

    private async Task CreateTierCInstance(string name)
    {
        if (_analysis is null) return;
        var tierD = _analysis.Route == "tier-d";
        var warning = new Wpf.Ui.Controls.MessageBox
        {
            Title = tierD
                ? "Compatibility Shim requires a managed copy"
                : "Native isolation requires a Windows profile",
            Content = tierD
                ? "This app requires a curated, version-gated compatibility adapter. AppMux will " +
                  "create a hidden standard Windows account, mirror a private copy, and modify only " +
                  "that managed copy after verifying exact executable, resource, and patch-signature " +
                  "hashes. Vendor updates with unknown hashes are refused. The installed original is " +
                  "unchanged; no service or driver is installed. Windows will request administrator approval."
                : "This app needs one hidden standard local account for a genuine separate Windows " +
                  "profile. If the app is installed only for your account, AppMux mirrors a private " +
                  "runnable copy into that isolated profile. Windows will request administrator " +
                  "approval. No service or driver is installed, and the original app is unchanged.",
            PrimaryButtonText = tierD ? "Create Compatibility Shim" : "Continue",
            CloseButtonText = "Cancel",
        };
        if (await warning.ShowDialogAsync() != Wpf.Ui.Controls.MessageBoxResult.Primary)
        {
            CreateButton.IsEnabled = true;
            return;
        }
        BeginProgress("Creating the instance record...", 15);
        var created = await Core.RunAppmuxAsync(
            "run", "--target", _target, "--instance", name, "--create-only");
        if (created.Code != 0)
        {
            FailProgress(created.Output);
            return;
        }
        SetProgress("Waiting for administrator approval...", 35, true);
        var elevated = await Core.RunElevatedAppmuxAsync(
            "tier-c", "prepare", "--app", _analysis.AppId, "--instance", name);
        if (elevated != 0)
        {
            FailProgress(elevated == 1223
                ? "Administrator approval was cancelled."
                : $"Strong isolation setup failed ({elevated}). The instance card was kept so setup can be retried.");
            return;
        }
        SetProgress("Isolation is ready. Launching the app...", 82);
        var launch = await Core.RunAppmuxLaunchAsync(
            "run", "--target", _target, "--app", _analysis.AppId, "--instance", name);
        if (launch.Code != 0)
        {
            FailProgress(launch.Output);
            return;
        }
        await CompleteProgress();
    }

    private async Task CreatePackageLabInstance(string name)
    {
        var consent = new Wpf.Ui.Controls.MessageBox
        {
            Title = "Experimental Package Lab",
            Content = "AppMux will make a locally signed copy with a new Windows identity. " +
                      "Continue only if this app is free and has no DRM, paid-license, anti-cheat, " +
                      "or driver restriction. The Store-installed original is not modified.",
            PrimaryButtonText = "I confirm and continue",
            CloseButtonText = "Cancel",
        };
        if (await consent.ShowDialogAsync() != Wpf.Ui.Controls.MessageBoxResult.Primary)
        {
            CreateButton.IsEnabled = true;
            return;
        }
        var stripServices = _analysis?.StripServices == true;
        if (stripServices)
        {
            var warning = new Wpf.Ui.Controls.MessageBox
            {
                Title = "Service-dependent features will be disabled",
                Content = "This package registers a system-wide Windows service that cannot be " +
                          "duplicated safely. AppMux will remove only that service declaration, its " +
                          "service capabilities, and service firewall rule from the copied manifest.\n\n" +
                          "Features backed by that service will be unavailable in the clone. The " +
                          "original package and service remain untouched.",
                PrimaryButtonText = "Create service-free instance",
                CloseButtonText = "Cancel",
            };
            if (await warning.ShowDialogAsync() != Wpf.Ui.Controls.MessageBoxResult.Primary)
            {
                CreateButton.IsEnabled = true;
                return;
            }
        }
        BeginProgress("Copying the package...", 12);
        await Core.RunAppmuxAsync("dev", "on");
        var prepareArgs = new List<string>
        {
            "package-lab", "prepare", "--target", _target, "--instance", name,
            "--confirm-free-no-drm",
        };
        if (stripServices) prepareArgs.Add("--strip-services");
        var prepare = await Core.RunAppmuxAsync(prepareArgs.ToArray());
        if (prepare.Code != 0)
        {
            await Core.RunAppmuxAsync("dev", "off");
            FailProgress(prepare.Output);
            return;
        }

        var steps = new[]
        {
            new[] { "package-lab", "pack", "--target", _target, "--instance", name },
            new[] { "package-lab", "sign", "--target", _target, "--instance", name, "--confirm-trust-dev-cert" },
        };
        foreach (var args in steps)
        {
            SetProgress(args[1] == "pack" ? "Packing the MSIX..." : "Signing the test package...",
                args[1] == "pack" ? 35 : 55);
            var (code, output) = await Core.RunAppmuxAsync(args);
            if (code != 0)
            {
                await Core.RunAppmuxAsync("dev", "off");
                FailProgress(output);
                return;
            }
        }

        if (!Core.IsPackageLabCertificateMachineTrusted())
        {
            SetProgress("Waiting for administrator approval...", 68, true);
            var code = await Core.RunElevatedAppmuxAsync(
                "package-lab", "trust-machine", "--target", _target, "--instance", name,
                "--confirm-machine-trust");
            if (code != 0)
            {
                await Core.RunAppmuxAsync("dev", "off");
                FailProgress(code == 1223
                    ? "Administrator approval was cancelled."
                    : $"Certificate trust failed ({code}).");
                return;
            }
        }

        SetProgress("Installing the test package...", 82);
        var install = await Core.RunAppmuxAsync(
            "package-lab", "install", "--target", _target, "--instance", name, "--confirm-sideload");
        if (install.Code != 0)
        {
            await Core.RunAppmuxAsync("dev", "off");
            FailProgress(install.Output);
            return;
        }
        SetProgress("Registering the new instance...", 94);
        var adopt = await Core.RunAppmuxAsync(
            "package-lab", "adopt", "--target", _target, "--instance", name);
        await Core.RunAppmuxAsync("dev", "off");
        if (adopt.Code != 0)
        {
            FailProgress(adopt.Output);
            return;
        }
        await CompleteProgress();
    }

    private void BeginProgress(string message, double value)
    {
        _busy = true;
        NameBox.IsEnabled = false;
        CreateButton.IsEnabled = false;
        CreateButton.Content = "Working...";
        CancelButton.IsEnabled = false;
        ErrorText.Visibility = Visibility.Collapsed;
        ProgressPanel.Visibility = Visibility.Visible;
        SetProgress(message, value);
    }

    private void SetProgress(string message, double value, bool indeterminate = false)
    {
        CreateProgress.IsIndeterminate = indeterminate;
        CreateProgress.Value = value;
        ProgressText.Text = message;
    }

    private async Task CompleteProgress()
    {
        SetProgress("Instance ready. The app has launched.", 100);
        CreateButton.Content = "Complete";
        await Task.Delay(650);
        if (_standalone)
            Close();
        else
            DialogResult = true;
    }

    private void FailProgress(string message)
    {
        _busy = false;
        NameBox.IsEnabled = true;
        CreateButton.IsEnabled = true;
        CreateButton.Content = "Retry";
        CancelButton.IsEnabled = true;
        ProgressPanel.Visibility = Visibility.Visible;
        SetProgress("Setup stopped. Review the message and try again.", 0);
        ShowError(string.IsNullOrWhiteSpace(message) ? "The operation failed." : message);
    }

    private void ShowError(string message)
    {
        ErrorText.Text = message;
        ErrorText.Visibility = Visibility.Visible;
    }

    private static bool IsValidName(string name) =>
        name.Length is >= 1 and <= 32 &&
        name.All(c => char.IsLetterOrDigit(c) || c is ' ' or '-' or '_' or '.');
}
