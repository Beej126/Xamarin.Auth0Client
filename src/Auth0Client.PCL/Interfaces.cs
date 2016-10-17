using System.Collections.Generic;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;

// ReSharper disable once CheckNamespace
namespace Auth0.SDK
{
  public interface IAuth0Client
  {
    string CallbackUrl { get; }
    IAuth0User CurrentUser { get; }
    IDeviceIdProvider DeviceIdProvider { get; }

    Task<JObject> GetDelegationToken(string api = "", string idToken = "", string refreshToken = "", string targetClientId = "", Dictionary<string, string> options = null);
    bool HasTokenExpired();
    Task<IAuth0User> LoginAsync(string connection, string userName, string password, bool withRefreshToken = false, string scope = "openid");
    Task<IAuth0User> LoginAsync(string connection = "", bool withRefreshToken = false, string scope = "openid", string title = null);
    void Logout();
    Task<JObject> RefreshToken(string refreshToken = "", Dictionary<string, string> options = null);
    Task<JObject> RenewIdToken(Dictionary<string, string> options = null);
  }

  public interface IAuth0User
  {
    string Auth0AccessToken { get; set; }
    string IdToken { get; set; }
    JObject Profile { get; set; }
    string RefreshToken { get; set; }
  }
}
