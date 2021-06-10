namespace AuthService
{
    public class DeviceAuthorizationViewModel : ConsentViewModel
    {
        public bool ConfirmUserCode { get; set; }

        public string UserCode { get; set; }
    }
}
