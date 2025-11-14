using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace authService.src.models
{
    /// <summary>
    /// Representa la información de inicio de sesión de un usuario
    /// </summary>
    public class Login
    {
        public Guid Id { get; set; }

    
        public List<string> Roles { get; set; } = new List<string>();

    }
}