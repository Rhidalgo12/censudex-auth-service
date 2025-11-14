using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNetCore.Identity;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using authService.src.models;
using System.Security.Claims;
using System.Threading.Tasks;
using authService.src.interfaces;

namespace authService.src.Services
{
    /// <summary>
    /// Servicio para la gestión de tokens JWT
    /// </summary>
    public class TokenService : ITokenService
    {
        /// <summary>
        /// Clave secreta para firmar los tokens JWT
        /// </summary>
        private readonly SymmetricSecurityKey _signingKey;
        /// <summary>
        /// Lista estática para almacenar los tokens JWT generados
        /// </summary>
        /// <typeparam name="string"></typeparam>
        /// <returns></returns>

        private static List<string> _Tokens = new List<string>();

        /// <summary>
        /// Constructor que inicializa la clave secreta para firmar los tokens JWT
        /// </summary>

        public TokenService(){
            var signingKey = Environment.GetEnvironmentVariable("JWT_SIGNING_KEY") ?? throw new ArgumentNullException("JWT_SIGNING_KEY environment variable is not set.");

            _signingKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(signingKey));
        }

        /// <summary>
        /// Genera un token JWT para un usuario dado
        /// </summary>
        /// <param name="login"></param>
        /// <returns></returns>

        public TokenResult GenerateToken(Login login)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, login.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            if(login.Roles != null)
            {
                foreach(var role in login.Roles)
                {
                    claims.Add(new Claim(ClaimTypes.Role, role));
                }
            }
            /// <summary>
            /// Credenciales de firma del token
            /// </summary>
            /// <returns></returns>
            var creds = new SigningCredentials(_signingKey, SecurityAlgorithms.HmacSha512Signature);

            var issuer = Environment.GetEnvironmentVariable("JWT_ISSUER") ?? throw new ArgumentNullException("JWT Issuer cannot be null or empty.");
            var audience = Environment.GetEnvironmentVariable("JWT_AUDIENCE") ?? throw new ArgumentNullException("JWT Audience cannot be null or empty.");

            var expires = DateTime.UtcNow.AddHours(1);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = expires,
                SigningCredentials = creds,
                Issuer = issuer,
                Audience = audience
            };
            /// <summary>
            /// Crea un token JWT basado en la descripción del token
            /// </summary>
            /// <returns></returns>
 
            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
 
            var tokenString = tokenHandler.WriteToken(token);
            _Tokens.Add(tokenString);
 
            return new TokenResult
            {
                Token = tokenString,
                Expires = expires
            };
        }

        /// <summary>
        /// Revoca un token JWT eliminándolo de la lista de tokens válidos
        /// </summary>
        /// <param name="token"></param>
        public void RevokeToken(string token)
        {
            _Tokens.Remove(token);
        }
        /// <summary>
        /// Valida un token JWT y devuelve los reclamos si es válido
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        public ClaimsPrincipal? ValidateToken(string token)
        {
            if(!_Tokens.Contains(token))
                return null;

            var tokenHandler = new JwtSecurityTokenHandler();
            var issuer = Environment.GetEnvironmentVariable("JWT_ISSUER") ?? throw new ArgumentNullException("JWT Issuer cannot be null or empty.");
            var audience = Environment.GetEnvironmentVariable("JWT_AUDIENCE") ?? throw new ArgumentNullException("JWT Audience cannot be null or empty.");
            
            /// <summary>
            /// Valida un token JWT y devuelve los reclamos si es válido
            /// </summary>
            /// <value></value>
            try
            {
                var validation = tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = _signingKey,
                    ValidateIssuer = true,
                    ValidIssuer = issuer,
                    ValidateAudience = true,
                    ValidAudience = audience,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                return validation;

            }

            catch
            {
                return null;
            }
        }

        
    }
}