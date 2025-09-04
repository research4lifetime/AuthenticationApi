using Microsoft.AspNetCore.Identity;
namespace ASPNETCoreIdentityAuthentication.Authentication.Models
{
    public class ApplicationUser : IdentityUser
    {
        // Add custom profile fields if needed
        public string? FullName { get; set; }
    }

}
