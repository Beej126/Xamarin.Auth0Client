using System.Drawing;
using System.Threading.Tasks;
using Xamarin.Auth;
#if __UNIFIED__
using UIKit;
#else
using MonoTouch.UIKit;
#endif

namespace Auth0.SDK
{
  public class PlatformUiContextIos
  {
    public UIViewController ViewController { get; }

    public PlatformUiContextIos(UIViewController viewController)
    {
      ViewController = viewController;
    }
  }
  public partial class Auth0Client
  {
    private readonly PlatformUiContextIos _platformUiContext;
    public Auth0Client(PlatformUiContextIos platformUiContext, string domain, string clientId) : this(domain, clientId)
    {
      _platformUiContext = platformUiContext;
    }

    public async Task<IAuth0User> LoginAsync(string connection = "", bool withRefreshToken = false,
      string scope = "openid", string title = null)
    {
      return CurrentUser ?? await LoginAsync(_platformUiContext.ViewController, connection, withRefreshToken, scope, title);
    }

    /// <summary>
    /// Log a user into an Auth0 application given a connection name.
    /// </summary>
    /// <param name="viewController" type="MonoTouch.UIKit.UIViewController">
    /// UIViewController used to display modal login UI on iPhone/iPods.
    /// </param>
    /// <param name="connection" type="string">
    /// The name of the connection to use in Auth0. Connection defines an Identity Provider.
    /// </param>
    /// <param name="withRefreshToken" type="bool">
    /// Specifies if it should return a refresh token or not.
    /// </param>
    /// <param name="scope" type="string">
    /// Space delimited, case sensitive list of OAuth 2.0 scope values.
    /// </param>
    /// <param name="title" type="string">
    /// Title displayed in the login screen, by default is null
    /// </param>
    /// <returns>
    /// Task that will complete when the user has finished authentication.
    /// </returns>
    public async Task<IAuth0User> LoginAsync(UIViewController viewController, string connection = "", bool withRefreshToken = false, string scope = "openid", string title = null)
    {
      return await SendLoginAsync(default(RectangleF), viewController, connection, withRefreshToken, scope, title);
    }

    /// <summary>
    /// Log a user into an Auth0 application given a connection name.
    /// </summary>
    /// <param name="rectangle" type="System.Drawing.RectangleF">
    /// The area in <paramref name="view"/> to anchor to.
    /// </param>
    /// <param name="view" type="MonoTouch.UIKit.UIView">
    /// UIView used to display a popover from on iPad.
    /// </param>
    /// <param name="connection" type="string">
    /// The name of the connection to use in Auth0. Connection defines an Identity Provider.
    /// </param>
    /// <param name="withRefreshToken" type="bool">
    /// Specifies if it should return a refresh token or not.
    /// </param>
    /// <param name="scope" type="string">
    /// Space delimited, case sensitive list of OAuth 2.0 scope values.
    /// </param>
    /// <param name="title" type="string">
    /// Title displayed in the login screen, by default is null
    /// </param>
    /// <returns>
    /// Task that will complete when the user has finished authentication.
    /// </returns>
    public async Task<IAuth0User> LoginAsync(RectangleF rectangle, UIView view, string connection = "", bool withRefreshToken = false, string scope = "openid", string title = null)
    {
      return await SendLoginAsync(rectangle, view, connection, withRefreshToken, scope, title);
    }

    /// <summary>
    /// Log a user into an Auth0 application given a connection name.
    /// </summary>
    /// <param name="barButtonItem" type="MonoTouch.UIKit.UIBarButtonItem">
    /// UIBarButtonItem used to display a popover from on iPad.
    /// </param>
    /// <param name="connection" type="string">
    /// The name of the connection to use in Auth0. Connection defines an Identity Provider.
    /// </param>
    /// <param name="withRefreshToken" type="bool">
    /// Specifies if it should return a refresh token or not.
    /// </param>
    /// <param name="scope" type="string">
    /// Space delimited, case sensitive list of OAuth 2.0 scope values.
    /// </param>
    /// <param name="title" type="string">
    /// Title displayed in the login screen, by default is null
    /// </param>
    /// <returns>
    /// Task that will complete when the user has finished authentication.
    /// </returns>
    public async Task<IAuth0User> LoginAsync(UIBarButtonItem barButtonItem, string connection = "", bool withRefreshToken = false, string scope = "openid", string title = null)
    {
      return await SendLoginAsync(default(RectangleF), barButtonItem, connection, withRefreshToken, scope, title);
    }

    private async Task<IAuth0User> SendLoginAsync(
      RectangleF rect,
      object view,
      string connection,
      bool withRefreshToken,
      string scope,
      string title)
    {
      // Launch server side OAuth flow using the GET endpoint
      scope = IncreaseScopeWithOfflineAccess(withRefreshToken, scope);

      var tcs = new TaskCompletionSource<IAuth0User>();
      var auth = await GetAuthenticator(connection, scope, title);

      var c = auth.GetUI();

      var controller = view as UIViewController;
      UIPopoverController popover = null;

      auth.Error += (o, e) =>
      {
        controller?.DismissViewController(true, null);
        popover?.Dismiss(true);

        var ex = e.Exception ?? new AuthException(e.Message);
        tcs.TrySetException(ex);
      };

      auth.Completed += (o, e) =>
      {
        controller?.DismissViewController(true, null);
        popover?.Dismiss(true);

        if (!e.IsAuthenticated)
        {
          tcs.TrySetCanceled();
        }
        else
        {
          SetupCurrentUser(e.Account.Properties);
          tcs.TrySetResult(CurrentUser);
        }
      };

      if (controller != null)
      {
        controller.PresentViewController(c, true, null);
      }
      else
      {
        var v = view as UIView;
        var barButton = view as UIBarButtonItem;
        popover = new UIPopoverController(c);

        if (barButton != null)
        {
          popover.PresentFromBarButtonItem(barButton, UIPopoverArrowDirection.Any, true);
        }
        else
        {
          popover.PresentFromRect(rect, v, UIPopoverArrowDirection.Any, true);
        }
      }

      return await tcs.Task;
    }

  }
}
