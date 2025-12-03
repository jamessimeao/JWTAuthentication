using JWTAuthentication.Dtos;
using JWTAuthentication.Entities;

namespace JWTAuthentication.Services
{
    public interface IAuthService
    {
        public Task<User?> RegisterAsync(UserDto userDto);
        public Task<TokenResponseDto?> LoginAsync(UserDto userDto);
    }
}
