using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using HelloStorageIdentity.Models;
using HelloStorageIdentity.Helpers;

namespace HelloStorageIdentity
{
    public class EmailService : IIdentityMessageService
    {
        public Task SendAsync(IdentityMessage message)
        {
            // Plug in your email service here to send an email.
            return Task.FromResult(0);
        }
    }

    public class SmsService : IIdentityMessageService
    {
        public Task SendAsync(IdentityMessage message)
        {
            // Plug in your SMS service here to send a text message.
            return Task.FromResult(0);
        }
    }

    // Configure the application user manager used in this application. UserManager is defined in ASP.NET Identity and is used by the application.
    public class ApplicationUserManager : UserManager<AzureTableUser>
    {

        public ApplicationUserManager(IUserStore<AzureTableUser> store)
            : base(store)
        {
        }

        public static ApplicationUserManager Create(IdentityFactoryOptions<ApplicationUserManager> options, IOwinContext context) 
        {
            var manager = new ApplicationUserManager(new AzureStore());
            // Configure validation logic for usernames
            manager.UserValidator = new UserValidator<AzureTableUser>(manager)
            {
                AllowOnlyAlphanumericUserNames = false,
                RequireUniqueEmail = true
            };

            // Configure validation logic for passwords
            manager.PasswordValidator = new PasswordValidator
            {
                RequiredLength = 6,
                RequireNonLetterOrDigit = true,
                RequireDigit = true,
                RequireLowercase = true,
                RequireUppercase = true,
            };

            // Configure user lockout defaults
            manager.UserLockoutEnabledByDefault = true;
            manager.DefaultAccountLockoutTimeSpan = TimeSpan.FromMinutes(5);
            manager.MaxFailedAccessAttemptsBeforeLockout = 5;

            // Register two factor authentication providers. This application uses Phone and Emails as a step of receiving a code for verifying the user
            // You can write your own provider and plug it in here.
            manager.RegisterTwoFactorProvider("Phone Code", new PhoneNumberTokenProvider<AzureTableUser>
            {
                MessageFormat = "Your security code is {0}"
            });
            manager.RegisterTwoFactorProvider("Email Code", new EmailTokenProvider<AzureTableUser>
            {
                Subject = "Security Code",
                BodyFormat = "Your security code is {0}"
            });
            //manager.EmailService = new EmailService();
            //manager.SmsService = new SmsService();
            var dataProtectionProvider = options.DataProtectionProvider;
            if (dataProtectionProvider != null)
            {
                manager.UserTokenProvider = 
                    new DataProtectorTokenProvider<AzureTableUser>(dataProtectionProvider.Create("ASP.NET Identity"));
            }
            return manager;
        }

        public override Task<IdentityResult> AccessFailedAsync(string userId)
        {
            return base.AccessFailedAsync(userId);
        }

        public override Task<IdentityResult> AddClaimAsync(string userId, Claim claim)
        {
            return base.AddClaimAsync(userId, claim);
        }

        public override Task<IdentityResult> AddLoginAsync(string userId, UserLoginInfo login)
        {
            return base.AddLoginAsync(userId, login);
        }

        public override Task<IdentityResult> AddPasswordAsync(string userId, string password)
        {
            return base.AddPasswordAsync(userId, password);
        }

        public override Task<IdentityResult> AddToRoleAsync(string userId, string role)
        {
            return base.AddToRoleAsync(userId, role);
        }

        public override Task<IdentityResult> AddToRolesAsync(string userId, params string[] roles)
        {
            return base.AddToRolesAsync(userId, roles);
        }

        public override Task<IdentityResult> ChangePasswordAsync(string userId, string currentPassword, string newPassword)
        {
            return base.ChangePasswordAsync(userId, currentPassword, newPassword);
        }

        public override Task<IdentityResult> ChangePhoneNumberAsync(string userId, string phoneNumber, string token)
        {
            return base.ChangePhoneNumberAsync(userId, phoneNumber, token);
        }

        public override Task<bool> CheckPasswordAsync(AzureTableUser user, string password)
        {
            return base.CheckPasswordAsync(user, password);
        }

        public override Task<IdentityResult> ConfirmEmailAsync(string userId, string token)
        {
            return base.ConfirmEmailAsync(userId, token);
        }

        public override Task<IdentityResult> CreateAsync(AzureTableUser user)
        {
            return base.CreateAsync(user);
        }

        public override Task<IdentityResult> CreateAsync(AzureTableUser user, string password)
        {
            return base.CreateAsync(user, password);
        }

        public override Task<ClaimsIdentity> CreateIdentityAsync(AzureTableUser user, string authenticationType)
        {
            return base.CreateIdentityAsync(user, authenticationType);
        }

        public override Task<IdentityResult> DeleteAsync(AzureTableUser user)
        {
            return base.DeleteAsync(user);
        }

        public override bool Equals(object obj)
        {
            return base.Equals(obj);
        }

        public override Task<AzureTableUser> FindAsync(string userName, string password)
        {
            return base.FindAsync(userName, password);
        }

        public override Task<AzureTableUser> FindAsync(UserLoginInfo login)
        {
            return base.FindAsync(login);
        }

        public override Task<AzureTableUser> FindByEmailAsync(string email)
        {
            return base.FindByEmailAsync(email);
        }

        public override Task<AzureTableUser> FindByIdAsync(string userId)
        {
            return base.FindByIdAsync(userId);
        }

        public override Task<AzureTableUser> FindByNameAsync(string userName)
        {
            return base.FindByNameAsync(userName);
        }

        public override Task<string> GenerateChangePhoneNumberTokenAsync(string userId, string phoneNumber)
        {
            return base.GenerateChangePhoneNumberTokenAsync(userId, phoneNumber);
        }

        public override Task<string> GenerateEmailConfirmationTokenAsync(string userId)
        {
            return base.GenerateEmailConfirmationTokenAsync(userId);
        }

        public override Task<string> GeneratePasswordResetTokenAsync(string userId)
        {
            return base.GeneratePasswordResetTokenAsync(userId);
        }

        public override Task<string> GenerateTwoFactorTokenAsync(string userId, string twoFactorProvider)
        {
            return base.GenerateTwoFactorTokenAsync(userId, twoFactorProvider);
        }

        public override Task<string> GenerateUserTokenAsync(string purpose, string userId)
        {
            return base.GenerateUserTokenAsync(purpose, userId);
        }

        public override Task<int> GetAccessFailedCountAsync(string userId)
        {
            return base.GetAccessFailedCountAsync(userId);
        }

        public override Task<IList<Claim>> GetClaimsAsync(string userId)
        {
            return base.GetClaimsAsync(userId);
        }

        public override Task<string> GetEmailAsync(string userId)
        {
            return base.GetEmailAsync(userId);
        }

        public override int GetHashCode()
        {
            return base.GetHashCode();
        }

        public override Task<bool> GetLockoutEnabledAsync(string userId)
        {
            return base.GetLockoutEnabledAsync(userId);
        }

        public override Task<DateTimeOffset> GetLockoutEndDateAsync(string userId)
        {
            return base.GetLockoutEndDateAsync(userId);
        }

        public override Task<IList<UserLoginInfo>> GetLoginsAsync(string userId)
        {
            return base.GetLoginsAsync(userId);
        }

        public override Task<string> GetPhoneNumberAsync(string userId)
        {
            return base.GetPhoneNumberAsync(userId);
        }

        public override Task<IList<string>> GetRolesAsync(string userId)
        {
            return base.GetRolesAsync(userId);
        }

        public override Task<string> GetSecurityStampAsync(string userId)
        {
            return base.GetSecurityStampAsync(userId);
        }

        public override Task<bool> GetTwoFactorEnabledAsync(string userId)
        {
            return base.GetTwoFactorEnabledAsync(userId);
        }

        public override Task<IList<string>> GetValidTwoFactorProvidersAsync(string userId)
        {
            return base.GetValidTwoFactorProvidersAsync(userId);
        }

        public override Task<bool> HasPasswordAsync(string userId)
        {
            return base.HasPasswordAsync(userId);
        }

        public override Task<bool> IsEmailConfirmedAsync(string userId)
        {
            return base.IsEmailConfirmedAsync(userId);
        }

        public override Task<bool> IsInRoleAsync(string userId, string role)
        {
            return base.IsInRoleAsync(userId, role);
        }

        public override Task<bool> IsLockedOutAsync(string userId)
        {
            return base.IsLockedOutAsync(userId);
        }

        public override Task<bool> IsPhoneNumberConfirmedAsync(string userId)
        {
            return base.IsPhoneNumberConfirmedAsync(userId);
        }

        public override Task<IdentityResult> NotifyTwoFactorTokenAsync(string userId, string twoFactorProvider, string token)
        {
            return base.NotifyTwoFactorTokenAsync(userId, twoFactorProvider, token);
        }

        public override void RegisterTwoFactorProvider(string twoFactorProvider, IUserTokenProvider<AzureTableUser, string> provider)
        {
            base.RegisterTwoFactorProvider(twoFactorProvider, provider);
        }

        public override Task<IdentityResult> RemoveClaimAsync(string userId, Claim claim)
        {
            return base.RemoveClaimAsync(userId, claim);
        }

        public override Task<IdentityResult> RemoveFromRoleAsync(string userId, string role)
        {
            return base.RemoveFromRoleAsync(userId, role);
        }

        public override Task<IdentityResult> RemoveFromRolesAsync(string userId, params string[] roles)
        {
            return base.RemoveFromRolesAsync(userId, roles);
        }

        public override Task<IdentityResult> RemoveLoginAsync(string userId, UserLoginInfo login)
        {
            return base.RemoveLoginAsync(userId, login);
        }

        public override Task<IdentityResult> RemovePasswordAsync(string userId)
        {
            return base.RemovePasswordAsync(userId);
        }

        public override Task<IdentityResult> ResetAccessFailedCountAsync(string userId)
        {
            return base.ResetAccessFailedCountAsync(userId);
        }

        public override Task<IdentityResult> ResetPasswordAsync(string userId, string token, string newPassword)
        {
            return base.ResetPasswordAsync(userId, token, newPassword);
        }

        public override Task SendEmailAsync(string userId, string subject, string body)
        {
            return base.SendEmailAsync(userId, subject, body);
        }

        public override Task SendSmsAsync(string userId, string message)
        {
            return base.SendSmsAsync(userId, message);
        }

        public override Task<IdentityResult> SetEmailAsync(string userId, string email)
        {
            return base.SetEmailAsync(userId, email);
        }

        public override Task<IdentityResult> SetLockoutEnabledAsync(string userId, bool enabled)
        {
            return base.SetLockoutEnabledAsync(userId, enabled);
        }

        public override Task<IdentityResult> SetLockoutEndDateAsync(string userId, DateTimeOffset lockoutEnd)
        {
            return base.SetLockoutEndDateAsync(userId, lockoutEnd);
        }

        public override Task<IdentityResult> SetPhoneNumberAsync(string userId, string phoneNumber)
        {
            return base.SetPhoneNumberAsync(userId, phoneNumber);
        }

        public override Task<IdentityResult> SetTwoFactorEnabledAsync(string userId, bool enabled)
        {
            return base.SetTwoFactorEnabledAsync(userId, enabled);
        }

        public override string ToString()
        {
            return base.ToString();
        }

        public override Task<IdentityResult> UpdateAsync(AzureTableUser user)
        {
            return base.UpdateAsync(user);
        }

        public override Task<IdentityResult> UpdateSecurityStampAsync(string userId)
        {
            return base.UpdateSecurityStampAsync(userId);
        }

        public override Task<bool> VerifyChangePhoneNumberTokenAsync(string userId, string token, string phoneNumber)
        {
            return base.VerifyChangePhoneNumberTokenAsync(userId, token, phoneNumber);
        }

        public override Task<bool> VerifyTwoFactorTokenAsync(string userId, string twoFactorProvider, string token)
        {
            return base.VerifyTwoFactorTokenAsync(userId, twoFactorProvider, token);
        }

        public override Task<bool> VerifyUserTokenAsync(string userId, string purpose, string token)
        {
            return base.VerifyUserTokenAsync(userId, purpose, token);
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
        }

        protected override Task<IdentityResult> UpdatePassword(IUserPasswordStore<AzureTableUser, string> passwordStore, AzureTableUser user, string newPassword)
        {
            return base.UpdatePassword(passwordStore, user, newPassword);
        }

        protected override Task<bool> VerifyPasswordAsync(IUserPasswordStore<AzureTableUser, string> store, AzureTableUser user, string password)
        {
            return base.VerifyPasswordAsync(store, user, password);
        }
    }

    // Configure the application sign-in manager which is used in this application.
    public class ApplicationSignInManager : SignInManager<AzureTableUser, string>
    {
        public ApplicationSignInManager(ApplicationUserManager userManager, IAuthenticationManager authenticationManager)
            : base(userManager, authenticationManager)
        {
        }

        //public override Task<ClaimsIdentity> CreateUserIdentityAsync(AzureTableUser user)
        //{
        //    return user.GenerateUserIdentityAsync((ApplicationUserManager)UserManager);
        //}

        public static ApplicationSignInManager Create(IdentityFactoryOptions<ApplicationSignInManager> options, IOwinContext context)
        {
            return new ApplicationSignInManager(context.GetUserManager<ApplicationUserManager>(), context.Authentication);
        }
    }
}
