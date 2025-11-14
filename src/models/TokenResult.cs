namespace authService.src.models
{
    /// <summary>
    /// Representa el resultado de la generación de un token JWT
    /// </summary>
    public class TokenResult
    {
        public string Token { get; set; } = string.Empty;
        public DateTime Expires { get; set; }
    }
}