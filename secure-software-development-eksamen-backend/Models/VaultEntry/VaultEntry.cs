namespace secure_software_development_eksamen_backend.Models;

public class VaultEntry
{
    public string Id { get; set; } = Guid.NewGuid().ToString(); 
    public int UserId { get; set; } 
    public string Name { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string EncryptedPassword { get; set; } = string.Empty; //AES-256
    public string Iv { get; set; } = string.Empty;
    public string Url { get; set; } = string.Empty;
    public string? Notes { get; set; }
    public DateTime? CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAt { get; set; } = DateTime.UtcNow;
    public User User { get; set; } = null!; // Navigation property
}