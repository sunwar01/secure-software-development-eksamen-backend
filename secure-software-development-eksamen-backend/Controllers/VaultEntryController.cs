using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using secure_software_development_eksamen_backend.Data;
using secure_software_development_eksamen_backend.Models;
using secure_software_development_eksamen_backend.Services;
using System.Security.Claims;
using Microsoft.AspNetCore.RateLimiting;
using secure_software_development_eksamen_backend.Models.Dto;

namespace secure_software_development_eksamen_backend.Controllers;

[ApiController]
[Route("api/vault")]
[Authorize]
public class VaultController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly AuthService _authService;
    

    public VaultController(ApplicationDbContext context, AuthService authService)
    {
        _context = context;
        _authService = authService;
    }

    [EnableRateLimiting("globalPolicy")]
    [HttpPost("createVaultEntry")]
    public async Task<IActionResult> Create([FromBody] VaultEntryCreate entry)
    {
        var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)!.Value);
        
        
        if (!HttpContext.Session.TryGetValue("EncryptionKey", out byte[]? userSpecificKey))
        {
            return Unauthorized("Session expired or encryption key not found. Please log in again.");
        }
        
        var (encryptedPassword, iv) = _authService.EncryptPassword(entry.Password, userSpecificKey);
        
        
        var newVaultEntry = new VaultEntry
        {
            Id = Guid.NewGuid().ToString(),
            UserId = userId,
            Name = entry.Name,
            Username = entry.Username,
            EncryptedPassword = encryptedPassword,
            Iv = iv,
            Url = entry.Url,
            Notes = entry.Notes,
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        };
        
        
       

        _context.VaultEntries.Add(newVaultEntry);
        await _context.SaveChangesAsync();
        
        
        return Ok(entry);
    }

    [EnableRateLimiting("globalPolicy")]
    [HttpGet("getVaultEntries")]
    public async Task<IActionResult> GetAll()
    {
        var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)!.Value);
        
        if (!HttpContext.Session.TryGetValue("EncryptionKey", out byte[]? userSpecificKey))
        {
            return Unauthorized("Session expired or encryption key not found. Please log in again.");
            
        }
        
        var entries = await _context.VaultEntries
            .Where(e => e.UserId == userId)
            .ToListAsync();
        
        var vaultEntryGetDtos = new List<VaultEntryGet>();
        
        foreach (var entry in entries)
        {
            var decryptedPassword = _authService.DecryptPassword(
                entry.EncryptedPassword,
                entry.Iv,
                userSpecificKey
            );
            
            var vaultEntryGetDto = new VaultEntryGet
            {
                Id = entry.Id, 
                UserId = userId,
                Name = entry.Name,
                Username = entry.Username,
                DecryptedPassword = decryptedPassword,
                Url = entry.Url,
                Notes = entry.Notes
            };
            
            vaultEntryGetDtos.Add(vaultEntryGetDto);
        }
        
        

        return Ok(vaultEntryGetDtos);
    }

   

    [EnableRateLimiting("globalPolicy")]
    [HttpDelete("deleteVaultEntry{id}")]
    public async Task<IActionResult> Delete(string id)
    {
        var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)!.Value);
        var entry = await _context.VaultEntries
            .FirstOrDefaultAsync(e => e.Id == id && e.UserId == userId);
        if (entry == null)
            return NotFound();

        _context.VaultEntries.Remove(entry);
        await _context.SaveChangesAsync();
        return Ok();
    }
}