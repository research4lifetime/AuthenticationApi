using ASPNETCoreIdentityAuthentication.Authentication.Data;
using ASPNETCoreIdentityAuthentication.Authentication.Models;
using ASPNETCoreIdentityAuthentication.Authentication.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;


namespace ASPNETCoreIdentityAuthentication.Authentication.Services
{




    public class TokenService : ITokenService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AuthDbContext _db;
        private readonly JwtOptions _opts;

        public TokenService(UserManager<ApplicationUser> userManager,
                            AuthDbContext db,
                            IOptions<JwtOptions> jwtOptions)
        {
            _userManager = userManager;
            _db = db;
            _opts = jwtOptions.Value;
        }

        public async Task<(string accessToken, RefreshToken refresh)> CreateTokensAsync(ApplicationUser user, string ipAddress)
        {
            var roles = await _userManager.GetRolesAsync(user);
            var access = CreateAccessToken(user, roles);

            // rotate: revoke old active tokens if you want single-session
            // await _db.RefreshTokens.Where(r => r.UserId == user.Id && r.IsActive).ForEachAsync(r => r.RevokedAtUtc = DateTime.UtcNow);

            var refresh = CreateRefreshToken(user.Id, ipAddress, _opts.RefreshTokenDays);
            _db.RefreshTokens.Add(refresh);
            await _db.SaveChangesAsync();

            return (access, refresh);
        }

        public string CreateAccessToken(ApplicationUser user, IEnumerable<string> roles)
        {
            var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id),
            new(JwtRegisteredClaimNames.Email, user.Email ?? string.Empty),
            new("name", user.FullName ?? user.UserName ?? string.Empty),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };
            claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_opts.Key));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(
                issuer: _opts.Issuer,
                audience: _opts.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(_opts.AccessTokenMinutes),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public RefreshToken CreateRefreshToken(string userId, string ipAddress, int days)
        {
            return new RefreshToken
            {
                UserId = userId,
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)), // consider hashing
                ExpiresAtUtc = DateTime.UtcNow.AddDays(days),
                CreatedAtUtc = DateTime.UtcNow,
                CreatedByIp = ipAddress
            };
        }
    }

    public class JwtOptions
    {
        public string Issuer { get; set; } = default!;
        public string Audience { get; set; } = default!;
        public string Key { get; set; } = default!;
        public int AccessTokenMinutes { get; set; } = 15;
        public int RefreshTokenDays { get; set; } = 14;
    }
}