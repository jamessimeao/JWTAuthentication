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
        public async Task<ActionResult<TokenResponseDto>> LoginAsync(UserDto userDto)
        {
            TokenResponseDto? token = await authService.LoginAsync(userDto);
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

        [Authorize(Roles = "Admin")]
        [HttpGet]
        public ActionResult AdminOnlyEndpoint()
        {
            return Ok("You are an admin.");
        }

        [Authorize]
        [HttpPost]
        public async Task<ActionResult<TokenResponseDto>> RefreshToken(RefreshTokenRequestDto refreshTokenRequestDto)
        {
            TokenResponseDto? tokenResponseDto = await authService.RefreshTokensAsync(refreshTokenRequestDto);
            if (tokenResponseDto != null)
            {
                return Ok(tokenResponseDto);
            }
            else
            {
                return Unauthorized("Invalid refresh token");
            }
        }
    }
}
