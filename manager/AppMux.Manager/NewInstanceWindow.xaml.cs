using System.IO;
using System.Windows;
using System.Windows.Input;

namespace AppMux.Manager;

public partial class NewInstanceWindow
{
    private readonly string _target;
    private readonly bool _standalone;
    private bool _packageLab;
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
            CreateButton.Content = "Build and install test instance";
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
                else if (_packageLab)
                {
                    CreateButton.Content = "Build and install test instance";
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
        if (e.Key == Key.Enter) OnCreate(sender, e);
        if (e.Key == Key.Escape) Close();
    }

    private void OnCancel(object sender, RoutedEventArgs e) => Close();

    private async void OnCreate(object sender, RoutedEventArgs e)
    {
        var name = NameBox.Text.Trim();
        if (!IsValidName(name))
        {
            ShowError("Use 1-32 characters: letters, digits, space, '-', '_', '.'");
            return;
        }

        CreateButton.IsEnabled = false;
        if (_analysis?.Route == "web-app")
        {
            await CreateWebInstance(name);
            return;
        }
        if (_analysis?.Route == "tier-c")
        {
            await CreateTierCInstance(name);
            return;
        }
        if (_packageLab)
        {
            await CreatePackageLabInstance(name);
            return;
        }

        var (code, output) = await Core.RunAppmuxAsync(
            "run", "--target", _target, "--instance", name);
        if (code != 0)
        {
            CreateButton.IsEnabled = true;
            ShowError(string.IsNullOrWhiteSpace(output) ? "Launch failed." : output);
            return;
        }
        Close();
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
        CreateButton.Content = "Opening isolated web app...";
        var result = await Core.RunAppmuxAsync(
            "web", "create", "--target", _target, "--instance", name);
        if (result.Code != 0)
        {
            CreateButton.IsEnabled = true;
            CreateButton.Content = "Create and launch";
            ShowError(result.Output);
            return;
        }
        Close();
    }

    private async Task CreateTierCInstance(string name)
    {
        if (_analysis is null) return;
        var warning = new Wpf.Ui.Controls.MessageBox
        {
            Title = "Strong isolation requires a Windows account",
            Content = "No verified profile recipe exists for this app. AppMux recommends one " +
                      "hidden standard local account for a genuine separate HKCU and AppData. " +
                      "Windows will request administrator approval. No service or driver is installed.",
            PrimaryButtonText = "Continue",
            CloseButtonText = "Cancel",
        };
        if (await warning.ShowDialogAsync() != Wpf.Ui.Controls.MessageBoxResult.Primary)
        {
            CreateButton.IsEnabled = true;
            return;
        }
        var created = await Core.RunAppmuxAsync(
            "run", "--target", _target, "--instance", name, "--create-only");
        if (created.Code != 0)
        {
            CreateButton.IsEnabled = true;
            ShowError(created.Output);
            return;
        }
        CreateButton.Content = "Waiting for administrator approval...";
        var elevated = await Core.RunElevatedAppmuxAsync(
            "tier-c", "prepare", "--app", _analysis.AppId, "--instance", name);
        if (elevated != 0)
        {
            await Core.RunAppmuxAsync("remove", "--app", _analysis.AppId, "--instance", name);
            CreateButton.IsEnabled = true;
            CreateButton.Content = "Create and launch";
            if (elevated != 1223) ShowError($"Strong isolation setup failed ({elevated}).");
            return;
        }
        var launch = await Core.RunAppmuxAsync(
            "run", "--target", _target, "--app", _analysis.AppId, "--instance", name);
        if (launch.Code != 0)
        {
            CreateButton.IsEnabled = true;
            ShowError(launch.Output);
            return;
        }
        Close();
    }

    private async Task CreatePackageLabInstance(string name)
    {
        var consent = new Wpf.Ui.Controls.MessageBox
        {
            Title = "Experimental Package Lab",
            Content = "AppMux will make a locally signed copy with a new Windows identity. " +
                      "Continue only if this app is free and has no DRM, paid-license, anti-cheat, " +
                      "or driver restriction. The Store-installed original is not modified.",
            PrimaryButtonText = "I confirm — continue",
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
        await Core.RunAppmuxAsync("dev", "on");
        CreateButton.Content = "Copying package...";
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
            CreateButton.IsEnabled = true;
            CreateButton.Content = "Retry";
            ShowError(prepare.Output);
            return;
        }

        var steps = new[]
        {
            new[] { "package-lab", "pack", "--target", _target, "--instance", name },
            new[] { "package-lab", "sign", "--target", _target, "--instance", name, "--confirm-trust-dev-cert" },
        };
        foreach (var args in steps)
        {
            CreateButton.Content = args[1] == "pack" ? "Packing MSIX..." : "Signing test package...";
            var (code, output) = await Core.RunAppmuxAsync(args);
            if (code != 0)
            {
                await Core.RunAppmuxAsync("dev", "off");
                CreateButton.IsEnabled = true;
                CreateButton.Content = "Retry";
                ShowError(output);
                return;
            }
        }

        if (!Core.IsPackageLabCertificateMachineTrusted())
        {
            CreateButton.Content = "Waiting for administrator approval...";
            var code = await Core.RunElevatedAppmuxAsync(
                "package-lab", "trust-machine", "--target", _target, "--instance", name,
                "--confirm-machine-trust");
            if (code != 0)
            {
                await Core.RunAppmuxAsync("dev", "off");
                CreateButton.IsEnabled = true;
                CreateButton.Content = "Retry";
                ShowError(code == 1223 ? "Administrator approval was cancelled." : $"Certificate trust failed ({code}).");
                return;
            }
        }

        CreateButton.Content = "Installing test package...";
        var install = await Core.RunAppmuxAsync(
            "package-lab", "install", "--target", _target, "--instance", name, "--confirm-sideload");
        if (install.Code != 0)
        {
            await Core.RunAppmuxAsync("dev", "off");
            CreateButton.IsEnabled = true;
            CreateButton.Content = "Retry";
            ShowError(install.Output);
            return;
        }
        var adopt = await Core.RunAppmuxAsync(
            "package-lab", "adopt", "--target", _target, "--instance", name);
        await Core.RunAppmuxAsync("dev", "off");
        if (adopt.Code != 0)
        {
            CreateButton.IsEnabled = true;
            CreateButton.Content = "Retry";
            ShowError(adopt.Output);
            return;
        }
        Close();
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
