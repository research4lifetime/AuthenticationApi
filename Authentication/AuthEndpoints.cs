using ASPNETCoreIdentityAuthentication.Authentication.Data;
using ASPNETCoreIdentityAuthentication.Authentication.Models;
using ASPNETCoreIdentityAuthentication.Authentication.Services;
using Microsoft.AspNetCore.Identity;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;

namespace ASPNETCoreIdentityAuthentication.Authentication
{
    public static class AuthExtensionEndpoints
    {
        record RegisterDto(string Email, string Password, string FullName);
        record LoginDto(string Email, string Password);
        record AuthResponse { public string AccessToken { get; set; } = ""; public string RefreshToken { get; set; } = ""; public int ExpiresIn { get; set; } }
        record RefreshRequest(string RefreshToken);
        record RevokeRequest(string RefreshToken);
        record RevokeAllRequest(string UserId);
        record ForgotPasswordDto(string Email);
        record ResetPasswordDto(string Email, string Token, string NewPassword);
        public static void MapRegisterUsersEndpoint(this RouteGroupBuilder app)
        {
            // Register

            app.MapPost("register", async (UserManager<ApplicationUser> userManager,
                RoleManager<IdentityRole> roleManager, RegisterDto dto) =>
            {
                var user = new ApplicationUser { UserName = dto.Email, Email = dto.Email, FullName = dto.FullName };
                var result = await userManager.CreateAsync(user, dto.Password);
                if (!result.Succeeded) return Results.BadRequest(result.Errors);

                // default role
                if (!await roleManager.RoleExistsAsync("user"))
                    await roleManager.CreateAsync(new IdentityRole("user"));
                await userManager.AddToRoleAsync(user, "user");

                return Results.Ok(new { message = "Registered" });
            });
        }
        public static void MapLoginEndpoint(this RouteGroupBuilder app, WebApplicationBuilder builder )
        {
            // Login
            app.MapPost("login", async (HttpContext http,
                SignInManager<ApplicationUser> signInManager,
                UserManager<ApplicationUser> userManager,
                ITokenService tokenSvc, LoginDto dto) =>
            {
                var user = await userManager.FindByEmailAsync(dto.Email);
                if (user == null) return Results.Unauthorized();

                var check = await signInManager.CheckPasswordSignInAsync(user, dto.Password, lockoutOnFailure: true);
                if (!check.Succeeded) return Results.Unauthorized();

                var (access, refresh) = await tokenSvc.CreateTokensAsync(user, http.Connection.RemoteIpAddress?.ToString() ?? "unknown");
                
                return Results.Ok(new AuthResponse { AccessToken = access, RefreshToken = refresh.Token, ExpiresIn = 60 * builder.Configuration.GetValue<int>("Jwt:AccessTokenMinutes") });
            });
        }

        public static void MapRefreshEndpoint(this RouteGroupBuilder app, WebApplicationBuilder builder)
        {
            // Refresh (rotate)
            app.MapPost("refresh", async (HttpContext http, AuthDbContext db,
                UserManager<ApplicationUser> userManager, ITokenService tokenSvc, RefreshRequest dto) =>
            {
                var existing = await db.RefreshTokens
                    .Include(r => r.User)
                    .FirstOrDefaultAsync(r => r.Token == dto.RefreshToken);

                if (existing == null || !existing.IsActive) return Results.Unauthorized();

                // rotate: revoke current and issue a new one
                existing.RevokedAtUtc = DateTime.UtcNow;
                existing.RevokedByIp = http.Connection.RemoteIpAddress?.ToString();
                var (access, newRefresh) = await tokenSvc.CreateTokensAsync(existing.User, existing.RevokedByIp ?? "unknown");
                existing.ReplacedByToken = newRefresh.Token;

                await db.SaveChangesAsync();
                return Results.Ok(new AuthResponse { AccessToken = access, RefreshToken = newRefresh.Token, ExpiresIn = 60 * builder.Configuration.GetValue<int>("Jwt:AccessTokenMinutes") });
            });
        }

        public static void MapLogoutEndpoint(this RouteGroupBuilder app)
        {
            // Logout (revoke a single refresh token)
            app.MapPost("logout",  async (AuthDbContext db, RevokeRequest dto) =>
            {
                var token = await db.RefreshTokens.FirstOrDefaultAsync(r => r.Token == dto.RefreshToken);
                if (token == null) return Results.Ok(); // idempotent
                token.RevokedAtUtc = DateTime.UtcNow;
                await db.SaveChangesAsync();
                return Results.Ok(new { message = "Logged out" });
            })
                .RequireAuthorization(new AuthorizeAttribute() { Policy= "AdminsOnly" });
        }

        public static void MaprevokeAllEndpoint(this RouteGroupBuilder app)
        {
            // Revoke all tokens for user
            app.MapPost("revoke-all", async (AuthDbContext db, UserManager<ApplicationUser> userManager, RevokeAllRequest dto) =>
            {
                var user = await userManager.FindByIdAsync(dto.UserId);
                if (user == null) return Results.NotFound();

                var tokens = db.RefreshTokens.Where(r => r.UserId == user.Id && r.IsActive);
                await tokens.ForEachAsync(t => t.RevokedAtUtc = DateTime.UtcNow);
                await db.SaveChangesAsync();
                return Results.Ok(new { message = "All tokens revoked" });
            });
        }

        public static void MapForgotPasswordEndpoint(this RouteGroupBuilder app)
        {

            // Forgot Password (send reset token – return it in response for demo; in prod, email it)
            app.MapPost("forgot-password", async (UserManager<ApplicationUser> userManager, ForgotPasswordDto dto) =>
            {
                var user = await userManager.FindByEmailAsync(dto.Email);
                if (user == null) return Results.Ok(); // don't reveal

                var token = await userManager.GeneratePasswordResetTokenAsync(user);
                // TODO: send token via email link containing token + email
                return Results.Ok(new { message = "Reset email sent", token }); // demo only
            });
        }

        public static void MapResetPasswordEndpoint(this RouteGroupBuilder app)
        {
            // Reset Password
            app.MapPost("reset-password", async (UserManager<ApplicationUser> userManager, ResetPasswordDto dto) =>
            {
                var user = await userManager.FindByEmailAsync(dto.Email);
                if (user == null) return Results.BadRequest();

                var result = await userManager.ResetPasswordAsync(user, dto.Token, dto.NewPassword);
                if (!result.Succeeded) return Results.BadRequest(result.Errors);

                return Results.Ok(new { message = "Password reset successful" });
            });
        }

        public static void MapProfileEndpoint(this RouteGroupBuilder app)
        {

            // Example protected endpoint
            app.MapGet("profile", async (UserManager<ApplicationUser> userManager, ClaimsPrincipal user) =>
            {
                var me = await userManager.GetUserAsync(user);
                if (me == null) return Results.Unauthorized();
                var roles = await userManager.GetRolesAsync(me);
                return Results.Ok(new { me.Email, me.FullName, roles });
            }).RequireAuthorization();


        }
    }
}


