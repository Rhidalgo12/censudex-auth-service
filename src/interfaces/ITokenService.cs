using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using authService.src.models;
using System.Security.Claims;

namespace authService.src.interfaces
{
    /// <summary>
    /// Interface for token service to create, remove and validate JWT tokens.
    /// </summary>
    public interface ITokenService
    {
        TokenResult GenerateToken(Login login);
        void RevokeToken(string token);
        ClaimsPrincipal? ValidateToken(string token);
    }
}