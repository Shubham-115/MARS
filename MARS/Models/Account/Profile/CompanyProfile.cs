namespace ProjectDemo.Models.Account.Profile
{
    public class CompanyProfile
    {

        public long CompanyID { get; set; }   // BIGINT IDENTITY
        public long UserID { get; set; }      // Foreign Key
         
        public string CompanyName { get; set; }
        public string RegistrationNumber { get; set; }
        public string GSTIN { get; set; }
        public string PAN { get; set; }
        public string ConstitutionOfFirm { get; set; }
        public string Address { get; set; }
        public string Tehsil { get; set; }
        public string District { get; set; }
        public string State { get; set; }
        public string ContactNo { get; set; }
        public string AuthorizedPerson { get; set; }
    }
}
