using System.ComponentModel.DataAnnotations;
using System.Runtime.InteropServices;

namespace MARS.Models.Account
{
    public class UserSignUp
    {
        [Required(ErrorMessage ="First Name is required")]
        [MinLength(2,ErrorMessage ="Enter valid Name")]
        [RegularExpression("^[a-zA-Z]+$", ErrorMessage = "Only letters are allowed")]
        public string FirstName { get; set; }



        [Required(ErrorMessage = "Last Name is required")]
        [RegularExpression("^[a-zA-Z]+$", ErrorMessage = "Only letters are allowed")]
        public string LastName { get; set; }

         


        [Required]       
        [RegularExpression("^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$", ErrorMessage = "Please enter a valid email address!")]
        public string EmailID { get; set; }
        
        
        [Required(ErrorMessage = "Mobile number is required")]
        [RegularExpression(@"^\d{10}$", ErrorMessage = "Mobile number must be 10 digits")]
        public string MobileNo { get; set; }

       // public string EncryptedEmail { get; set; }
       // public string EncryptedMobileNo { get; set; }



    }
}
