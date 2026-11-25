using System.Windows;
using System.Windows.Controls;

namespace Conexoes.App.Views;

public partial class TabToolbar : UserControl
{
    public static readonly DependencyProperty ExtraContentProperty =
        DependencyProperty.Register(nameof(ExtraContent), typeof(object), typeof(TabToolbar));

    public TabToolbar() => InitializeComponent();

    /// <summary>Controles de filtro específicos da aba, exibidos ao lado da busca.</summary>
    public object? ExtraContent
    {
        get => GetValue(ExtraContentProperty);
        set => SetValue(ExtraContentProperty, value);
    }
}
