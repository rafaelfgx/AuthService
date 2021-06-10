namespace AuthService
{
    public class ConsentOptions
    {
        public static readonly string InvalidSelectionErrorMessage = "Invalid selection";

        public static readonly string MustChooseOneErrorMessage = "You must pick at least one permission";

        public static bool EnableOfflineAccess = true;

        public static string OfflineAccessDescription = "Access to your applications and resources, even when you are offline";

        public static string OfflineAccessDisplayName = "Offline Access";
    }
}
