using JWTAuthentication.Dtos;
using JWTAuthentication.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.JsonWebTokens;

namespace JWTAuthentication.Controllers
{
    [ApiController]
    [Route("api/[controller]/[action]")]
    public class AuthController(IConfiguration configuration) : ControllerBase
    {
        // Temporary, until there is no database
        private static User user = new User();

        [HttpPost]
        public ActionResult<User> Register(UserDto userDto)
        {
            string passwordHash = new PasswordHasher<User>().HashPassword(user, userDto.Password);
            user.Username = userDto.Username;
            user.PasswordHash = passwordHash;
            return Ok(user);
        }

        [HttpPost]
        public ActionResult<string> Login(UserDto userDto)
        {
            bool authenticated = false;
            if(userDto.Username == user.Username)
            {
                PasswordVerificationResult result = new PasswordHasher<User>().
                                                        VerifyHashedPassword(user, user.PasswordHash, userDto.Password);
                
                 if(result == PasswordVerificationResult.Success)
                {
                    authenticated = true;
                }
            }

            if (authenticated)
            {
                const string token = "success";
                return Ok(token);
            }
            else
            {
                return BadRequest("Wrong username or password.");
            }
        }

        private string CreateToken(User user)
        {
            Dictionary<string, object> claims = new Dictionary<string, object>()
            {
                [ClaimTypes.Name] = user.Username
            };
            string config = configuration.GetValue<string>("AppSettings:Token")!;
            byte[] data = Encoding.UTF8.GetBytes(config);
            SymmetricSecurityKey key = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(data);
            SigningCredentials credentials = new SigningCredentials(key,SecurityAlgorithms.HmacSha512);
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
    }
}
