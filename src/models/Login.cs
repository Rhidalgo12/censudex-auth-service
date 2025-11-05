using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace authService.src.models
{
    public class Login
    {
        public Guid Id { get; set; }

        public List<string> Roles { get; set; }

    }
}