using System.ComponentModel.DataAnnotations;

namespace MARS.Models.Account
{
    public class PasswordChange
    {

        [Required]
        [MinLength(6)]
        [RegularExpression("^((?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0 - 9])|(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[^a-zA-Z0-9])|(?=.*?[A-Z])(?=.*?[0 - 9])(?=.*?[^a-zA-Z0-9])|(?=.*?[a-z])(?=.*?[0 - 9])(?=.*?[^a-zA-Z0-9])).{6,}$")]
        public string PasswordHash { get; set; }
        [Required]
        public string ConfirmPassword { get; set; }
    }
}
