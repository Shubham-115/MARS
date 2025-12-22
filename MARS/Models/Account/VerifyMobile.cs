using System.ComponentModel.DataAnnotations;

namespace MARS.Models.Account
{
    public class VerifyMobile
    {
        [Required(ErrorMessage = "Mobile number is required")]
        [RegularExpression(@"^\d{10}$", ErrorMessage = "Mobile number must be 10 digits")]
        public string MobileNo { get; set; }

        [Required]
        [MinLength(6)]
        public string OTP { get; set; }
        public bool isSendOTP { get; set; }
    }
}
