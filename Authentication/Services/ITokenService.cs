using ASPNETCoreIdentityAuthentication.Authentication.Models;

namespace ASPNETCoreIdentityAuthentication.Authentication.Services
{
    public interface ITokenService
    {
        Task<(string accessToken, RefreshToken refresh)> CreateTokensAsync(ApplicationUser user, string ipAddress);
        string CreateAccessToken(ApplicationUser user, IEnumerable<string> roles);
        RefreshToken CreateRefreshToken(string userId, string ipAddress, int days);
    }

    
}
