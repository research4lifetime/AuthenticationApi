namespace ASPNETCoreIdentityAuthentication.Authentication.Models
{
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;

    public class RefreshToken
    {
        [Key] public int Id { get; set; }
        [Required] public string Token { get; set; } = default!;   // consider hashing in production
        [Required] public string UserId { get; set; } = default!;
        [ForeignKey(nameof(UserId))] public ApplicationUser User { get; set; } = default!;
        public DateTime ExpiresAtUtc { get; set; }
        public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
        public string? CreatedByIp { get; set; }
        public DateTime? RevokedAtUtc { get; set; }
        public string? RevokedByIp { get; set; }
        public string? ReplacedByToken { get; set; }               // for rotation
        public bool IsActive => RevokedAtUtc == null && DateTime.UtcNow <= ExpiresAtUtc;
    }
}
