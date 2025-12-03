using JWTAuthentication.Data;
using JWTAuthentication.Dtos;
using JWTAuthentication.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JWTAuthentication.Services
{
    public class AuthService(IConfiguration configuration, UserDbContext dbContext) : IAuthService
    {
        public async Task<User?> RegisterAsync(UserDto userDto)
        {
            // Check if user alredy exists
            User? user = await dbContext.Users.FirstOrDefaultAsync(u => u.Username == userDto.Username);
            if(user != null)
            {
                Console.WriteLine("User already exists.");
                return null;
            }

            // If the user doesn't exist, create a new user
            User newUser = new User();
            string passwordHash = new PasswordHasher<User>().HashPassword(newUser, userDto.Password);
            newUser.Username = userDto.Username;
            newUser.PasswordHash = passwordHash;

            // Add the new user to the database
            dbContext.Users.Add(newUser);
            dbContext.SaveChanges();

            // Return the new user
            return newUser;

        }

        public async Task<TokenResponseDto?> LoginAsync(UserDto userDto)
        {
            User? user = await dbContext.Users.FirstOrDefaultAsync(u => u.Username == userDto.Username);
            if (user != null)
            {
                PasswordVerificationResult result = new PasswordHasher<User>().
                                                        VerifyHashedPassword(user, user.PasswordHash, userDto.Password);

                if (result == PasswordVerificationResult.Success)
                {
                    TokenResponseDto tokenResponseDto = await CreateTokenResponse(user);
                    return tokenResponseDto;
                }
            }
            return null;
        }

        private string CreateToken(User user)
        {
            Dictionary<string, object> claims = new Dictionary<string, object>()
            {
                [ClaimTypes.Name] = user.Username,
                [ClaimTypes.NameIdentifier] = user.Id.ToString(),
                [ClaimTypes.Role] = user.Role,
            };
            string config = configuration.GetValue<string>("AppSettings:Token")!;
            byte[] data = Encoding.UTF8.GetBytes(config);
            SymmetricSecurityKey key = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(data);
            SigningCredentials credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha512);
            SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor()
            {
                Issuer = configuration.GetValue<string>("AppSettings:Issuer")!,
                Audience = configuration.GetValue<string>("AppSettings:Audience")!,
                Claims = claims,
                Expires = DateTime.UtcNow.AddDays(1),
                SigningCredentials = credentials
            };

            return new JsonWebTokenHandler().CreateToken(tokenDescriptor);
        }

        private string GenerateRefreshToken()
        {
            // Make random bytes
            byte[] randomBytes = new byte[32];
            using RandomNumberGenerator rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);

            // Create refresh token from random bytes
            string refreshToken = Convert.ToBase64String(randomBytes);
            return refreshToken;
        }

        private async Task<string> GenerateAnsSaveRefreshTokenAsync(User user)
        {
            string refreshToken = GenerateRefreshToken();
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(7);

            dbContext.Users.Update(user);

            await dbContext.SaveChangesAsync();
            return refreshToken;
        }

        private async Task<TokenResponseDto> CreateTokenResponse(User user)
        {
            string accessToken = CreateToken(user);
            string refreshToken = await GenerateAnsSaveRefreshTokenAsync(user);
            TokenResponseDto tokenResponseDto = new TokenResponseDto()
            {
                AccessToken = accessToken,
                RefreshToken = refreshToken,
            };
            return tokenResponseDto;
        }

        private async Task<User?> ValidateRefreshTokenAsync(int userId, string refreshToken)
        {
            User? user = await dbContext.Users.FirstOrDefaultAsync(u => u.Id == userId);
            if(user != null)
            {
                if(user.RefreshToken == refreshToken && user.RefreshTokenExpiryTime >= DateTime.UtcNow)
                {
                    return user;
                }
            }
            return null;
        }

        public async Task<TokenResponseDto?> RefreshTokensAsync(RefreshTokenRequestDto refreshTokenRequestDto)
        {
            User? user = await ValidateRefreshTokenAsync(refreshTokenRequestDto.UserId, refreshTokenRequestDto.RefreshToken);
            if(user == null){
                return null;
            }
            TokenResponseDto tokenResponseDto = await CreateTokenResponse(user);
            return tokenResponseDto;
        }
    }
}
