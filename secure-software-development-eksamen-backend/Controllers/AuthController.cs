using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using secure_software_development_eksamen_backend.Data;
using secure_software_development_eksamen_backend.Models;
using secure_software_development_eksamen_backend.Models.Dto;
using secure_software_development_eksamen_backend.Services;


namespace secure_software_development_eksamen_backend.Controllers;

  [ApiController]
    [Route("api/auth")]
    public class AuthController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly AuthService _authService;
        private readonly IConfiguration _config;

        public AuthController(ApplicationDbContext context, AuthService authService, IConfiguration config)
        {
            _context = context;
            _authService = authService;
            _config = config;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] UserRegister model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var existingUser = await _context.Users.FirstOrDefaultAsync(u => u.Username == model.Username);
            if (existingUser != null)
                return BadRequest("Username already exists");

            var user = new User
            {
                Username = model.Username,
                PasswordHash = _authService.HashPassword(model.Password),
                Salt = _authService.GenerateSalt()
                
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return Ok(new { Message = "User registered successfully" });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] UserLogin model)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == model.Username);
            if (user == null || !_authService.VerifyPassword(model.Password, user.PasswordHash))
                return Unauthorized("Invalid credentials");
            
            byte[] salt = user.Salt; 
            byte[] encryptionKey = _authService.GenerateEncryptionKey(model.Password, salt); 

            // Gem encryptionKey i hukommelse for en session. 
            HttpContext.Session.Set("EncryptionKey", encryptionKey);
            
            

            var accessToken = GenerateJwtToken(user);
            var refreshToken = await GenerateAndStoreRefreshToken(user);
            
            Response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
            {
                HttpOnly = true, 
                Secure = _config.GetValue<bool>("CookieSettings:Secure"), 
                // Skiftet til at bruge værdi ud fra environment
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddDays(1),
                // skiftet fra 7 dage til 1 dag, da det ville given en potentiel hacker et mindre vindue
                Path = "/api/auth"
            });

            return Ok(new { AccessToken = accessToken, EncryptionKey = encryptionKey });
        }

        
        
        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)!.Value);
            var tokens = await _context.RefreshTokens.Where(t => t.UserId == userId).ToListAsync();
            _context.RefreshTokens.RemoveRange(tokens);
            await _context.SaveChangesAsync();
            
            HttpContext.Session.Clear();

            Response.Cookies.Delete("refreshToken", new CookieOptions
            {
                HttpOnly = true,
                Secure = _config.GetValue<bool>("CookieSettings:Secure"), 
                // Skiftet til at bruge værdi ud fra environment
                SameSite = SameSiteMode.Strict,
                Path = "/api/auth"
            });
            
            return Ok(new { Message = "Logged out successfully" });
        }
        
        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshTokenRequest request)
        {
            if (string.IsNullOrEmpty(request.RefreshToken))
                return BadRequest("Refresh token is required");

            var hashedToken = HashToken(request.RefreshToken);
            var token = await _context.RefreshTokens
                .FirstOrDefaultAsync(t => t.Token == hashedToken && t.ExpiryDate > DateTime.UtcNow);

            if (token == null)
                return Unauthorized("Invalid or expired refresh token");

            var user = await _context.Users.FindAsync(token.UserId);
            if (user == null)
                return Unauthorized("User not found");

            var newAccessToken = GenerateJwtToken(user);
            
            await _context.RefreshTokens.Where(t => t.Id == token.Id).ExecuteDeleteAsync();
            var newRefreshToken = await GenerateAndStoreRefreshToken(user);
            
            Response.Cookies.Append("refreshToken", newRefreshToken, new CookieOptions
            {
                HttpOnly = true, 
                Secure = _config.GetValue<bool>("CookieSettings:Secure"), 
                // Skiftet til at bruge værdi ud fra environment
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddDays(1),
                // skiftet fra 7 dage til 1 dag, da det ville given en potentiel hacker et mindre vindue
                Path = "/api/auth"
            });
            
            return Ok(new { AccessToken = newAccessToken});
        }
        
        
        
        private string GenerateJwtToken(User user)
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Username)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]!));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(15),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        
      

        private async Task<string> GenerateAndStoreRefreshToken(User user)
        {
            var existingTokens = await _context.RefreshTokens
                .Where(t => t.UserId == user.Id)
                .ToListAsync();
            _context.RefreshTokens.RemoveRange(existingTokens);

            var tokenBytes = RandomNumberGenerator.GetBytes(32);
            var refreshToken = Convert.ToBase64String(tokenBytes);

            var tokenEntity = new RefreshToken
            {
                UserId = user.Id,
                Token = HashToken(refreshToken),
                ExpiryDate = DateTime.UtcNow.AddDays(7)
            };

            _context.RefreshTokens.Add(tokenEntity);
            await _context.SaveChangesAsync();

            return refreshToken;
        }

        private string HashToken(string token)
        {
            using var sha256 = SHA256.Create();
            var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(token));
            return Convert.ToBase64String(bytes);
        }
}