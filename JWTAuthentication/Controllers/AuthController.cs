using JWTAuthentication.Dtos;
using JWTAuthentication.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace JWTAuthentication.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private static User user = new User();

        [HttpPost("register")]
        public ActionResult<User> Register(UserDto userDto)
        {
            string hashedPassword = new PasswordHasher<User>().HashPassword(user, userDto.Password);
            user.Username = userDto.Username;
            user.PasswordHash = hashedPassword;
            return Ok(user);
        }

    }
}
