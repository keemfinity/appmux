using System.Windows;
using System.Windows.Media;
using Wpf.Ui.Appearance;
using Wpf.Ui.Controls;

namespace AppMux.Manager;

public static class ThemeService
{
    public static string Mode { get; private set; } = "System";

    static ThemeService()
    {
        ApplicationThemeManager.Changed += (theme, _) => ApplyBrandPalette(theme);
    }

    public static void ApplySaved()
    {
        Apply(Core.LoadManagerSettings().Theme, false);
    }

    public static void SetMode(string mode)
    {
        Apply(mode, true);
    }

    public static void ConfigureWindow(Window window)
    {
        if (Mode == "System")
            SystemThemeWatcher.Watch(window, WindowBackdropType.Acrylic, false);
        else
            SystemThemeWatcher.UnWatch(window);
    }

    private static void Apply(string mode, bool persist)
    {
        Mode = mode is "Dark" or "Light" ? mode : "System";
        var theme = Mode switch
        {
            "Dark" => ApplicationTheme.Dark,
            "Light" => ApplicationTheme.Light,
            _ => ApplicationThemeManager.GetSystemTheme() == SystemTheme.Dark
                ? ApplicationTheme.Dark
                : ApplicationTheme.Light,
        };
        ApplicationThemeManager.Apply(theme, WindowBackdropType.Acrylic, false);
        ApplicationAccentColorManager.Apply(Color.FromRgb(21, 87, 242), theme, false);
        ApplyBrandPalette(theme);
        foreach (Window window in Application.Current.Windows)
            ConfigureWindow(window);
        if (persist)
            Core.SaveManagerSettings(new ManagerSettings { Theme = Mode });
    }

    private static void ApplyBrandPalette(ApplicationTheme theme)
    {
        var resources = Application.Current.Resources;
        var dark = theme == ApplicationTheme.Dark;
        resources["SubtleTextBrush"] = Brush(dark ? "#A9BFC6D6" : "#FF5F6B7C");
        resources["AccentTextBrush"] = Brush(dark ? "#FF6DDCEB" : "#FF1557F2");
        resources["GlassCardBorderBrush"] = Brush(dark ? "#35FFFFFF" : "#2607163F");
        resources["IconTileBrush"] = Brush(dark ? "#18FFFFFF" : "#1207163F");
        resources["GlassCardBrush"] = Gradient(
            dark ? "#25FFFFFF" : "#EFFFFFFF",
            dark ? "#12FFFFFF" : "#DDF2F4F8");
        resources["GlassCardHoverBrush"] = Gradient(
            dark ? "#34FFFFFF" : "#FFFFFFFF",
            dark ? "#20FFFFFF" : "#E9F2F6FC");
        resources["BrandWordmarkBrush"] = Wordmark(dark);
    }

    private static SolidColorBrush Brush(string value)
    {
        var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(value));
        brush.Freeze();
        return brush;
    }

    private static LinearGradientBrush Gradient(string start, string end)
    {
        var brush = new LinearGradientBrush
        {
            StartPoint = new Point(0, 0),
            EndPoint = new Point(1, 1),
            GradientStops = new GradientStopCollection
            {
                new((Color)ColorConverter.ConvertFromString(start), 0),
                new((Color)ColorConverter.ConvertFromString(end), 1),
            },
        };
        brush.Freeze();
        return brush;
    }

    private static LinearGradientBrush Wordmark(bool dark)
    {
        var app = (Color)ColorConverter.ConvertFromString(dark ? "#FFF8FBFF" : "#FF07163F");
        var mux = (Color)ColorConverter.ConvertFromString("#FF1557F2");
        var brush = new LinearGradientBrush
        {
            StartPoint = new Point(0, 0),
            EndPoint = new Point(1, 0),
            GradientStops = new GradientStopCollection
            {
                new(app, 0), new(app, 0.46), new(mux, 0.47), new(mux, 1),
            },
        };
        brush.Freeze();
        return brush;
    }
}
