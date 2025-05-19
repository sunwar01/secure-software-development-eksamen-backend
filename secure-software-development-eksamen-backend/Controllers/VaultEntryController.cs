using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using secure_software_development_eksamen_backend.Data;
using secure_software_development_eksamen_backend.Models;
using secure_software_development_eksamen_backend.Services;
using System.Security.Claims;
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

    [HttpPost("createVaultEntry")]
    public async Task<IActionResult> Create([FromBody] VaultEntryCreate entry)
    {
        var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)!.Value);
        
        
        if (!HttpContext.Session.TryGetValue("EncryptionKey", out byte[]? userSpecificKey))
        {
            return Unauthorized("Session expired or encryption key not found. Please log in again.");
        }
        
        var (encryptedPassword, iv) = _authService.EncryptPassword(entry.Password, userSpecificKey);

        //Create vaultEntry Object from vaultentrycreate
        
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
        
        foreach (var entry in entries)
        {
            entry.EncryptedPassword = _authService.DecryptPassword(entry.EncryptedPassword, entry.Iv, userSpecificKey);
        }

        return Ok(entries);
    }

    [HttpPut("updateVaultEntry{id}")]
    public async Task<IActionResult> Update(string id, [FromBody] VaultEntry updatedEntry)
    {
        var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)!.Value);
       
        if (!HttpContext.Session.TryGetValue("EncryptionKey", out byte[]? userSpecificKey))
        {
            return Unauthorized("Session expired or encryption key not found. Please log in again.");
        }

        var entry = await _context.VaultEntries
            .FirstOrDefaultAsync(e => e.Id == id && e.UserId == userId);
        if (entry == null)
            return NotFound();

       
        var (encryptedPassword, iv) = _authService.EncryptPassword(updatedEntry.EncryptedPassword, userSpecificKey);
        entry.Name = updatedEntry.Name;
        entry.Username = updatedEntry.Username;
        entry.EncryptedPassword = encryptedPassword;
        entry.Iv = iv;
        entry.Url = updatedEntry.Url;
        entry.Notes = updatedEntry.Notes;
        entry.UpdatedAt = DateTime.UtcNow;

        await _context.SaveChangesAsync();

        
        entry.EncryptedPassword = _authService.DecryptPassword(encryptedPassword, iv, userSpecificKey);
        return Ok(entry);
    }

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