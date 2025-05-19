using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace secure_software_development_eksamen_backend.Migrations
{
    /// <inheritdoc />
    public partial class AddUserEncryptionKey : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "Password",
                table: "VaultEntries",
                newName: "Iv");

            migrationBuilder.AddColumn<string>(
                name: "EncryptedPassword",
                table: "VaultEntries",
                type: "longtext",
                nullable: false)
                .Annotation("MySql:CharSet", "utf8mb4");

            migrationBuilder.AddColumn<string>(
                name: "EncryptionKey",
                table: "Users",
                type: "longtext",
                nullable: false)
                .Annotation("MySql:CharSet", "utf8mb4");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "EncryptedPassword",
                table: "VaultEntries");

            migrationBuilder.DropColumn(
                name: "EncryptionKey",
                table: "Users");

            migrationBuilder.RenameColumn(
                name: "Iv",
                table: "VaultEntries",
                newName: "Password");
        }
    }
}
