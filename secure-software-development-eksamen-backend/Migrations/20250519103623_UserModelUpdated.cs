using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace secure_software_development_eksamen_backend.Migrations
{
    /// <inheritdoc />
    public partial class UserModelUpdated : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "EncryptionKey",
                table: "Users");

            migrationBuilder.AddColumn<byte[]>(
                name: "Salt",
                table: "Users",
                type: "longblob",
                nullable: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Salt",
                table: "Users");

            migrationBuilder.AddColumn<string>(
                name: "EncryptionKey",
                table: "Users",
                type: "longtext",
                nullable: false)
                .Annotation("MySql:CharSet", "utf8mb4");
        }
    }
}
