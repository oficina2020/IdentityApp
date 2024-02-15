using Api.DTO.Account;
using Api.DTOs.Account;
using Api.Models;
using Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using System;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly JWTService _jWtService;
        private readonly SignInManager<Models.User> _signInManager;
        private readonly UserManager<Models.User> _userManager;
        private readonly EmailService _emailService;
        private readonly IConfiguration _config;

        //El UserManager es una clase concreta que administra al usuario.Esta clase crea,
        //actualiza y elimina usuarios.Tiene métodos para encontrar un usuario por ID de usuario, Nombre de usuario y correo electrónico.
        //UserManager también proporciona la funcionalidad para agregar reclamos, eliminar reclamos, agregar y eliminar roles, etc.
        //También genera hash de contraseña, valida usuarios, etc.
        //SignInManager es una clase concreta que maneja el inicio de sesión del usuario desde la aplicación.
        //SignInManager es responsable de autenticar a un usuario, es decir, iniciar y cerrar sesión.
        //Emite la cookie de autenticación al usuario.

        public AccountController(JWTService jWtService, 
                                 SignInManager<Models.User> signInManager, 
                                 UserManager<Models.User> userManager,
                                 EmailService emailService,
                                 IConfiguration config)
        {
            _jWtService    = jWtService;
            _signInManager = signInManager;
            _userManager   = userManager;
            _emailService  = emailService;
            _config        = config;
        }

        [Authorize]
        [HttpGet("refresh-user-token")]
        public async Task<ActionResult<UserDto>> RefereshUserToken()
        {
            var user = await _userManager.FindByNameAsync(User.FindFirst(ClaimTypes.Email)?.Value);

            return await CreateApplicationUserDto(user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto model)
        {
            var user = await _userManager.FindByNameAsync(model.UserName);
            if (user == null) return Unauthorized("Invalid username or password");

            if (user.EmailConfirmed == false) return Unauthorized("Please confirm your email.");

            var result = await _signInManager.CheckPasswordSignInAsync(user, model.Password, false);

            if (!result.Succeeded) return Unauthorized("Usuario inválido o password");

            return await CreateApplicationUserDto(user);
        }


        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterDto model)
        {
            if (await CheckEmailExistsAsync(model.Email))
            {
                return BadRequest($"An existing account is using {model.Email}, email address. Por favor, inténtelo con otra dirección de correo electrónico");
            }

            var userToAdd = new Models.User
            {
                FirstName      = model.FirstName.ToLower(),
                LastName       = model.LastName.ToLower(),
                UserName       = model.Email.ToLower(),
                Email          = model.Email.ToLower(),
            };

            //Creamos el usuario 
            var result = await _userManager.CreateAsync(userToAdd, model.Password);
            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }

            try
            {
                if (await SendConfirmEMailAsync(userToAdd))
                {
                    return Ok(new JsonResult(new { title = "Account Created", message = "Your account has been created, please confrim your email address" }));
                }

                return BadRequest("Failed to send email. Please contact admin");
            }
            catch (Exception)
            {
                return BadRequest("Failed to send email. Please contact admin");
            }


            //return Ok("Su cuenta ha sido creada, ahora puede ingresar");
        }


        #region Private Helper Methods

        private async Task<bool> SendConfirmEMailAsync(User user)
        {
            //Creamos el Token
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            token     = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
            var url   = $"{_config["JWT:ClientUrl"]}/{_config["Email:ConfirmEmailPath"]}?token={token}&email={user.Email}";

            var body  = $"<p>Hello: {user.FirstName} {user.LastName}</p>" +
                "<p>Please confirm your email address by clicking on the following link.</p>" +
                $"<p><a href=\"{url}\">Click here</a></p>" +
                "<p>Thank you,</p>" +
                $"<br>{_config["Email:ApplicationName"]}";

            var emailSend = new EmailSendDto(user.Email, "Confirm your email", body);

            return await _emailService.SendEmailAsync(emailSend);
        }
        private async Task<UserDto> CreateApplicationUserDto(Models.User user)
        {
            return new UserDto
            {
                FirstName = user.FirstName,
                LastName = user.LastName,
                JWT = await _jWtService.CreateJWT(user),
            };
        }

        //Verifica que el email exista en la base de datos y devuelve un booleano
        private async Task<bool> CheckEmailExistsAsync(string email)
        {
            return await _userManager.Users.AnyAsync(x => x.Email == email.ToLower());
        }

        #endregion Private Helper Methods

    }
}
