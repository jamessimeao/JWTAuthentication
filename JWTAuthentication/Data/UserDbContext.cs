using JWTAuthentication.Entities;
using Microsoft.EntityFrameworkCore;

namespace JWTAuthentication.Data
{
    public class UserDbContext(DbContextOptions<UserDbContext> options) : DbContext(options)
    {
        DbSet<User> Users { get; set; }
    }
}
