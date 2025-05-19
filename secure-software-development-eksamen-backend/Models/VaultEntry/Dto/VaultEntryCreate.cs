namespace secure_software_development_eksamen_backend.Models.Dto;

public class VaultEntryCreate
{

    public string Name { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty; 
    public string Url { get; set; } = string.Empty;
    public string? Notes { get; set; }
    
    
}