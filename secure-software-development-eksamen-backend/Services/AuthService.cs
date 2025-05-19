using System.Text;
using Microsoft.EntityFrameworkCore;
using secure_software_development_eksamen_backend.Data;

namespace secure_software_development_eksamen_backend.Services;

using System.Security.Cryptography;



/*
 * Vi har bruge PBKDF2 med 128-bit salt og 600.000 iterationer, samt SHA256 som hash-algoritme.
 * 600.000 iterationer er valgt ud fra hvad Owasp anbefaler.
 * (https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
 * Dette har vi valgt ud fra at vi gerne vil have så få third party dependencies som muligt.
 * Et andet alternativ som vi havde kigget på er Argon2, som er mere sikker i forbindelse med gpu og asic bruteforce.
 * Dette ville dog have krævet et third party library.
 * https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id
 */

public class AuthService
{
    
    private readonly ApplicationDbContext _context;
    public AuthService(ApplicationDbContext context)
    {
        _context = context;
    }
    
    public string HashPassword(string password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16); 
        // 128-bit salt
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 600000, HashAlgorithmName.SHA256); 
        // 600.000 iterations + SHA256. 
        byte[] hash = pbkdf2.GetBytes(32); 
        // 256-bit hash
        byte[] hashBytes = new byte[48]; 
        Array.Copy(salt, 0, hashBytes, 0, 16);
        Array.Copy(hash, 0, hashBytes, 16, 32);
        return Convert.ToBase64String(hashBytes);
    }

    public bool VerifyPassword(string password, string storedHash)
    {
        byte[] hashBytes = Convert.FromBase64String(storedHash);
        byte[] salt = new byte[16];
        Array.Copy(hashBytes, 0, salt, 0, 16);
        byte[] storedHashValue = new byte[32];
        Array.Copy(hashBytes, 16, storedHashValue, 0, 32);

        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 600000, HashAlgorithmName.SHA256);
        byte[] hash = pbkdf2.GetBytes(32);
        for (int i = 0; i < 32; i++)
        {
            if (storedHashValue[i] != hash[i])
                return false;
        }
        return true;
    }
    
    
    //AES-256
    public (string EncryptedPassword, string Iv) EncryptPassword(string password, byte[] userSpecificKey)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        using var pbkdf2 = new Rfc2898DeriveBytes(userSpecificKey, salt, 600000, HashAlgorithmName.SHA256);
        byte[] key = pbkdf2.GetBytes(32);

        using var aes = Aes.Create();
        aes.Key = key;
        aes.GenerateIV();
        byte[] iv = aes.IV;

        using var encryptor = aes.CreateEncryptor(aes.Key, iv);
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        byte[] encrypted = encryptor.TransformFinalBlock(passwordBytes, 0, passwordBytes.Length);

        byte[] result = new byte[salt.Length + encrypted.Length];
        Array.Copy(salt, 0, result, 0, salt.Length);
        Array.Copy(encrypted, 0, result, salt.Length, encrypted.Length);

        return (Convert.ToBase64String(result), Convert.ToBase64String(iv));
    }

    public string DecryptPassword(string encryptedPassword, string iv, byte[] userSpecificKey)
    {
        byte[] encryptedBytes = Convert.FromBase64String(encryptedPassword);
        byte[] ivBytes = Convert.FromBase64String(iv);

        byte[] salt = new byte[16];
        byte[] encryptedData = new byte[encryptedBytes.Length - 16];
        Array.Copy(encryptedBytes, 0, salt, 0, 16);
        Array.Copy(encryptedBytes, 16, encryptedData, 0, encryptedData.Length);

        using var pbkdf2 = new Rfc2898DeriveBytes(userSpecificKey, salt, 600000, HashAlgorithmName.SHA256);
        byte[] key = pbkdf2.GetBytes(32);

        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = ivBytes;

        using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
        byte[] decrypted = decryptor.TransformFinalBlock(encryptedData, 0, encryptedData.Length);
        return Encoding.UTF8.GetString(decrypted);
    }
    
    public byte[] GenerateEncryptionKey(string password, byte[] salt)
    {
        using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 600000, HashAlgorithmName.SHA256);
        byte[] key = pbkdf2.GetBytes(32);
        byte[] keyBytes = new byte[48];
        Array.Copy(salt, 0, keyBytes, 0, 16);
        Array.Copy(key, 0, keyBytes, 16, 32);
        return keyBytes;
    }
    
    public byte[] GenerateSalt()
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        
        return salt;
    }
    

    
    

   
    
  
    
    
}
    

    
    
