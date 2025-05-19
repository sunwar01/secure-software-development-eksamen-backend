using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using secure_software_development_eksamen_backend.Data;
using secure_software_development_eksamen_backend.Models;
using secure_software_development_eksamen_backend.Services;
using System.Security.Claims;

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

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] VaultEntry entry)
    {
        var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)!.Value);
        var userSpecificKey = await _authService.GetEncryptionKeyAsync(userId);
        
        var (encryptedPassword, iv) = _authService.EncryptPassword(entry.EncryptedPassword, userSpecificKey);

        entry.UserId = userId;
        entry.EncryptedPassword = encryptedPassword;
        entry.Iv = iv;
        entry.CreatedAt = DateTime.UtcNow;
        entry.UpdatedAt = DateTime.UtcNow;

        _context.VaultEntries.Add(entry);
        await _context.SaveChangesAsync();
        
        entry.EncryptedPassword = _authService.DecryptPassword(encryptedPassword, iv, userSpecificKey);
        return Ok(entry);
    }

    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)!.Value);
        var userSpecificKey = await _authService.GetEncryptionKeyAsync(userId);

        var entries = await _context.VaultEntries
            .Where(e => e.UserId == userId)
            .ToListAsync();
        
        foreach (var entry in entries)
        {
            entry.EncryptedPassword = _authService.DecryptPassword(entry.EncryptedPassword, entry.Iv, userSpecificKey);
        }

        return Ok(entries);
    }

    [HttpPut("{id}")]
    public async Task<IActionResult> Update(string id, [FromBody] VaultEntry updatedEntry)
    {
        var userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)!.Value);
        var userSpecificKey = await _authService.GetEncryptionKeyAsync(userId);

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

    [HttpDelete("{id}")]
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