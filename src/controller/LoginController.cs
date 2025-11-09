using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using authService.src.interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using authService.src.models;
using authService.src.dtos;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace authService.src.controller
{

    [ApiController]
    [Route("api/[controller]")]
    public class LoginController : ControllerBase
    {

        private readonly ITokenService _tokenService;

        public LoginController(ITokenService tokenService)
        {
            _tokenService = tokenService;
        }


        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] Login login)
        {
            if (login == null)
            {
                return BadRequest("Invalid login request.");
            }

            var token = _tokenService.GenerateToken(login);
            var result = new
            {
                Token = token
            };  
            return Ok(result);

        }

        [HttpGet]
        [Authorize]
        public IActionResult ValidateToken(){
            var token = Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
            
            var validation = _tokenService.ValidateToken(token);

            if (validation==null){
                return Unauthorized("Invalid token.");
            }

            var result = new
            {
                Id = validation.FindFirstValue(ClaimTypes.NameIdentifier),
                Roles = validation.FindAll(ClaimTypes.Role).Select(r => r.Value)
            };
            return Ok(result);  
        }

        [HttpPost("logout")]
        [Authorize]
        public IActionResult Logout(){
            var token = Request.Headers["Authorization"].ToString().Replace("Bearer ", "");
            _tokenService.RevokeToken(token);
            var response = new
            {
                Message = "Token revoked successfully."
            };
            return Ok(response);
        }
        
        
    }
}