using System.Threading.Tasks;
using Android.OS;

namespace Auth0.SDK
{
	public class DeviceIdProvider : IDeviceIdProvider
	{
		public Task<string> GetDeviceId()
		{
			return Task.FromResult(string.Format("{0} {1}", Build.Brand, Build.Model));
		}
	}
}

