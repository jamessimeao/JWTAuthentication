using JWTAuthentication.Dtos;
using JWTAuthentication.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace JWTAuthentication.Controllers
{
    [ApiController]
    public class AuthController : ControllerBase
    [Route("api/[controller]/[action]")]
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
    }
}
