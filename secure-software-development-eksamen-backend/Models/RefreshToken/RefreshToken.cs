namespace secure_software_development_eksamen_backend.Models;

public class RefreshToken
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public string Token { get; set; } = string.Empty;
    
    public DateTime ExpiryDate { get; set; }
    
    public User User { get; set; } = null!; // Navigation property
}