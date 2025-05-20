namespace secure_software_development_eksamen_backend.Models.Dto;

public class VaultEntryGet
{
    public string Id { get; set; }  
    public int UserId { get; set; } 
    public string Name { get; set; } 
    public string Username { get; set; } 
    public string DecryptedPassword { get; set; } 
    public string Url { get; set; } 
    public string? Notes { get; set; }
}