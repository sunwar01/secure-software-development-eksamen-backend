using Microsoft.EntityFrameworkCore;
using secure_software_development_eksamen_backend.Models;

namespace secure_software_development_eksamen_backend.Data;

public class ApplicationDbContext : DbContext
{
    public DbSet<User> Users { get; set; }
    public DbSet<RefreshToken> RefreshTokens { get; set; }
    public DbSet<VaultEntry> VaultEntries { get; set; }

    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // User 
        modelBuilder.Entity<User>()
            .HasIndex(u => u.Username)
            .IsUnique(); // Brugernavn skal være unikt

        // RefreshToken 
        modelBuilder.Entity<RefreshToken>()
            .HasOne(rt => rt.User)
            .WithOne(u => u.RefreshToken)
            .HasForeignKey<RefreshToken>(rt => rt.UserId)
            .OnDelete(DeleteBehavior.Cascade); // Slet refreshtoken når en bruger bliver slettet

        // VaultEntry 
        modelBuilder.Entity<VaultEntry>()
            .HasOne(ve => ve.User)
            .WithMany(u => u.VaultEntries)
            .HasForeignKey(ve => ve.UserId)
            .OnDelete(DeleteBehavior.Cascade); // Slet vaultentries når en bruger bliver slettet

        base.OnModelCreating(modelBuilder);
    }
}