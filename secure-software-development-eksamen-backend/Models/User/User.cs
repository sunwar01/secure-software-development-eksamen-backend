namespace secure_software_development_eksamen_backend.Models;

public class User
{
    public int Id { get; set; } 
    public string Username { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public byte[] Salt { get; set; }
    public RefreshToken? RefreshToken { get; set; }
    public List<VaultEntry> VaultEntries { get; set; } = new(); // En til mange
}