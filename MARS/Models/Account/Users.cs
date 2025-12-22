namespace MARS.Models.Accounts
{
    public class Users
    {

        public long UserId { get; set; }
        public string MobileNo { get; set; }

        public string EmailID { get; set; }

        public string PasswordHash { get; set; }
         
        public string OTPCode { get; set; }
        public DateTime OTPGeneratedAt { get; set; }
        public bool EmailVerified { get; set; }

        public bool MobileVerified { get; set; }

        public bool status { get; set; }

        public string FirstName { get; set; }
        public string LastName { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime LastLoginAt { get; set; }

        public DateTime CreatedBy { get; set; }
    }
}
