using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace authService.src.dtos
{
    /// <summary>
    /// DTO para la solicitud de inicio de sesión
    /// </summary>
    public class LoginDTO
    {
        public required string Email { get; set; }

        public required string Password { get; set; }
    }
}