using Api.DTO.Account;
using Api.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
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

        //El UserManager es una clase concreta que administra al usuario.Esta clase crea,
        //actualiza y elimina usuarios.Tiene métodos para encontrar un usuario por ID de usuario, Nombre de usuario y correo electrónico.
        //UserManager también proporciona la funcionalidad para agregar reclamos, eliminar reclamos, agregar y eliminar roles, etc.
        //También genera hash de contraseña, valida usuarios, etc.
        //SignInManager es una clase concreta que maneja el inicio de sesión del usuario desde la aplicación.
        //SignInManager es responsable de autenticar a un usuario, es decir, iniciar y cerrar sesión.
        //Emite la cookie de autenticación al usuario.

        public AccountController(JWTService jWtService, SignInManager<Models.User> signInManager, UserManager<Models.User> userManager)
        {
            _jWtService = jWtService;
            _signInManager = signInManager;
            _userManager = userManager;
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
                EmailConfirmed = true
            };

            //Creamos el usuario 
            var result = await _userManager.CreateAsync(userToAdd, model.Password);
            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }

            return Ok("Su cuenta ha sido creada, ahora puede ingresar");
        }


        #region Private Helper Methods
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
