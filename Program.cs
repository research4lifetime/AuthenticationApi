using ASPNETCoreIdentityAuthentication.Authentication;
using ASPNETCoreIdentityAuthentication.Authentication.Data;
using ASPNETCoreIdentityAuthentication.Authentication.Models;
using ASPNETCoreIdentityAuthentication.Authentication.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<JwtOptions>(builder.Configuration.GetSection("Jwt"));

builder.Services.AddDbContext<AuthDbContext>(opts =>
    opts.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));


builder.Services.AddIdentity<ApplicationUser, IdentityRole>(opts =>
{
    opts.Password.RequiredLength = 6;
    opts.User.RequireUniqueEmail = true;
})
.AddEntityFrameworkStores<AuthDbContext>();
//.AddRoles<IdentityRole>()
//.AddDefaultTokenProviders(); // for reset password & email confirm



var jwt = builder.Configuration.GetSection("Jwt").Get<JwtOptions>()!;
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
})

    .AddJwtBearer(o =>
    {
        o.TokenValidationParameters = new()
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwt.Issuer,
            ValidAudience = jwt.Audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.Key)),
            ClockSkew = TimeSpan.Zero
        };
    });

builder.Services.AddAuthorizationBuilder()
.AddPolicy("AdminsOnly", policy =>
        policy
            .RequireRole("admin")
            //.RequireClaim(ClaimTypes.Role, "admin")
            //.RequireClaim("Roles", "admin")
            );

builder.Services.AddAuthorization();
builder.Services.AddScoped<ITokenService, TokenService>();


builder.Services.AddCors(p => p.AddDefaultPolicy(policy =>
    policy
    .AllowAnyOrigin()
    //.WithOrigins("http://localhost:8080")
    .AllowAnyHeader().AllowAnyMethod())); // tighten in prod

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();





var app = builder.Build();
app.UseSwagger(); app.UseSwaggerUI();


app.UseCors();
app.UseAuthentication();
app.UseAuthorization();


app.UseHttpsRedirection();
var apiGroup = app.MapGroup("/api/auth/");
apiGroup.MapRegisterUsersEndpoint();
apiGroup.MapLoginEndpoint(builder);
apiGroup.MapRefreshEndpoint(builder);
apiGroup.MapLogoutEndpoint();
apiGroup.MaprevokeAllEndpoint();
apiGroup.MapForgotPasswordEndpoint();
apiGroup.MapResetPasswordEndpoint();
var apiGroupProfile = app.MapGroup("/api/");
apiGroupProfile.MapProfileEndpoint();

//Seeding the required data.
// Ensure the database is created
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var dbContext = services.GetRequiredService<AuthDbContext>();

    // Apply pending migrations
    await dbContext.Database.MigrateAsync();

    // Seed roles and admin user
    await IdentitySeeder.SeedRolesAndAdminAsync(services);
}


app.Run();

