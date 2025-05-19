using System.ComponentModel.DataAnnotations;

namespace secure_software_development_eksamen_backend.Models.Dto;

public class UserRegister
{
    [Required(ErrorMessage = "Username is required")]
    [StringLength(20, MinimumLength = 5, ErrorMessage = "Username must be between 5 and 20 characters")]
    [RegularExpression(@"^[a-zA-Z0-9_-]+$", ErrorMessage = "Username can only contain letters, numbers, underscores, and hyphens")]
    public string Username { get; set; } = String.Empty;
    
    
    [Required(ErrorMessage = "Password is required")]
    [StringLength(50, MinimumLength = 8, ErrorMessage = "Password must be between 8 and 50 characters")]
    [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*?_])[A-Za-z\d!@#$%^&*?_]+$", 
        ErrorMessage = "Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character (!@#$%^&*?_)")]
    public string Password { get; set; } = String.Empty;
}