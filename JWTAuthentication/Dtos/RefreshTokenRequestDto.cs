namespace JWTAuthentication.Dtos
{
    public class RefreshTokenRequestDto
    {
        public required int UserId { get; set; }
        public required string RefreshToken { get; set; }
    }
}
