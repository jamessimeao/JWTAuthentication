using JWTAuthentication.Dtos;
using JWTAuthentication.Entities;
using JWTAuthentication.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JWTAuthentication.Controllers
{
    [ApiController]
    [Route("api/[controller]/[action]")]
    public class AuthController(IAuthService authService) : ControllerBase
    {
        [HttpPost]
        public async Task<ActionResult<User>> RegisterAsync(UserDto userDto)
        {
            User? user = await authService.RegisterAsync(userDto);
            if(user != null)
            {
                return Ok(user);
            }
            else
            {
                return BadRequest("Username already exists.");
            }
        }

        [HttpPost]
        public async Task<ActionResult<string>> LoginAsync(UserDto userDto)
        {
            string? token = await authService.LoginAsync(userDto);
            if(token != null)
            {
                return Ok(token);
            }
            else
            {
                return BadRequest("Wrong username or password.");
            }
        }

        [Authorize]
        [HttpGet]
        public ActionResult AuthenticatedOnlyEndpoint()
        {
            return Ok("You are authenticated.");
        }
    }
}
