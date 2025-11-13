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
    public class TokenService : ITokenService
    {
        private readonly SymmetricSecurityKey _signingKey;

        private static List<string> _Tokens = new List<string>();

        public TokenService(){
            var signingKey = Environment.GetEnvironmentVariable("JWT_SIGNING_KEY") ?? throw new ArgumentNullException("JWT_SIGNING_KEY environment variable is not set.");

            _signingKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(signingKey));
        }

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


        public void RevokeToken(string token)
        {
            _Tokens.Remove(token);
        }

        public ClaimsPrincipal? ValidateToken(string token)
        {
            if(!_Tokens.Contains(token))
                return null;

            var tokenHandler = new JwtSecurityTokenHandler();
            var issuer = Environment.GetEnvironmentVariable("JWT_ISSUER") ?? throw new ArgumentNullException("JWT Issuer cannot be null or empty.");
            var audience = Environment.GetEnvironmentVariable("JWT_AUDIENCE") ?? throw new ArgumentNullException("JWT Audience cannot be null or empty.");
            

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