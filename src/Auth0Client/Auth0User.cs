using System.Collections.Generic;
using Newtonsoft.Json.Linq;

namespace Auth0.SDK
{
	public class Auth0User : IAuth0User
	{
		public Auth0User()
		{
		}

		public Auth0User(IDictionary<string, string> accountProperties)
		{
			Auth0AccessToken = accountProperties.ContainsKey("access_token") ? accountProperties["access_token"] : string.Empty;
			IdToken = accountProperties.ContainsKey("id_token") ? accountProperties["id_token"] : string.Empty;
			Profile = accountProperties.ContainsKey("profile") ? accountProperties["profile"].ToJson() : null;
			RefreshToken = accountProperties.ContainsKey("refresh_token") ? accountProperties["refresh_token"] : string.Empty;
		}

		public string Auth0AccessToken { get; set; }

		public string IdToken { get; set; }

        public string RefreshToken { get; set; }

		public JObject Profile { get; set; }

	}

	internal static class Extensions
	{
		internal static JObject ToJson(this string jsonString)
		{
			return JObject.Parse(jsonString);
		}
	}
}
