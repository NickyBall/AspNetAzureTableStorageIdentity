using HelloStorageIdentity.Entities;
using HelloStorageIdentity.Models;
using Microsoft.AspNet.Identity;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Table;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Web;

namespace HelloStorageIdentity.Helpers
{
    public class AzureStore : IUserStore<AzureTableUser>,
                                IUserEmailStore<AzureTableUser>,
                                IUserRoleStore<AzureTableUser>,
                                IUserPasswordStore<AzureTableUser>,
                                IUserLockoutStore<AzureTableUser, string>,
                                IUserTwoFactorStore<AzureTableUser, string>
    {
        private readonly CloudTable UserTable;
        public AzureStore()
        {
            string ConnectionString = ConfigurationManager.AppSettings["AzureStorageConnectionString"];
            CloudTableClient StorageClient = CloudStorageAccount.Parse(ConnectionString).CreateCloudTableClient();
            UserTable = StorageClient.GetTableReference("HelloUser");
            UserTable.CreateIfNotExistsAsync();
        }

        public Task AddToRoleAsync(AzureTableUser user, string roleName) => Task.Run(() =>
        {
            user.Roles.Add(roleName);
        });

        public async Task CreateAsync(AzureTableUser user)
        {
            user.LockOutEndDate = DateTimeOffset.Now;
            user.Roles = new List<string>()
            {
                "admin", "mod"
            };
            user.Claims = new List<string>() { "c1", "c2" };
            TableResult Result = await UserTable.ExecuteAsync(TableOperation.InsertOrReplace(user.ToEntity()));
        }

        public async Task DeleteAsync(AzureTableUser user)
        {
            TableResult RetrieveResult = await UserTable.ExecuteAsync(TableOperation.Retrieve<UserDataEntity>("UserData", user.UserName));
            if (RetrieveResult.HttpStatusCode == HttpStatusCode.OK.GetHashCode())
            {
                TableResult Result = await UserTable.ExecuteAsync(TableOperation.Delete((UserDataEntity)RetrieveResult.Result));
            }
        }

        public void Dispose()
        {
            
        }

        public async Task<AzureTableUser> FindByEmailAsync(string email)
        {
            AzureTableUser User = null;
            TableQuerySegment<UserDataEntity> Segment = await UserTable.ExecuteQuerySegmentedAsync(new TableQuery<UserDataEntity>().Where($"Email eq '{email}'").Take(1), null);
            if (Segment.Count() > 0) User = Segment.FirstOrDefault().ToUser();
            return User;
        }

        public async Task<AzureTableUser> FindByIdAsync(string userId)
        {
            AzureTableUser User = null;
            TableResult Result = await UserTable.ExecuteAsync(TableOperation.Retrieve<UserDataEntity>("UserData", userId));
            UserDataEntity Entity = (UserDataEntity)Result.Result;
            if (Entity != null) User = Entity.ToUser();
            return User;
        }

        public async Task<AzureTableUser> FindByNameAsync(string userName)
        {
            AzureTableUser User = null;
            TableResult Result = await UserTable.ExecuteAsync(TableOperation.Retrieve<UserDataEntity>("UserData", userName));
            UserDataEntity Entity = (UserDataEntity)Result.Result;
            if (Entity != null) User = Entity.ToUser();
            return User;
        }

        public Task<int> GetAccessFailedCountAsync(AzureTableUser user) => Task.FromResult(0);

        public Task<string> GetEmailAsync(AzureTableUser user) => Task.FromResult(user.Email);

        public Task<bool> GetEmailConfirmedAsync(AzureTableUser user) => Task.FromResult(true);

        public Task<bool> GetLockoutEnabledAsync(AzureTableUser user) => Task.FromResult(false);

        public Task<DateTimeOffset> GetLockoutEndDateAsync(AzureTableUser user) => Task.FromResult(user.LockOutEndDate);

        public async Task<string> GetPasswordHashAsync(AzureTableUser user)
        {
            return await Task.FromResult(user.Password);
        }

        public Task<IList<string>> GetRolesAsync(AzureTableUser user) => Task.FromResult(user.Roles);

        public Task<bool> GetTwoFactorEnabledAsync(AzureTableUser user) => Task.FromResult(false);

        public Task<bool> HasPasswordAsync(AzureTableUser user) => Task.FromResult(true);

        public Task<int> IncrementAccessFailedCountAsync(AzureTableUser user)
        {
            throw new NotImplementedException();
        }

        public Task<bool> IsInRoleAsync(AzureTableUser user, string roleName) => Task.FromResult(user.Roles.Any(r => r.Equals(roleName)));

        public Task RemoveFromRoleAsync(AzureTableUser user, string roleName) => Task.Run(() =>
        {
            user.Roles.Remove(roleName);
        });

        public Task ResetAccessFailedCountAsync(AzureTableUser user) => Task.CompletedTask;

        public Task SetEmailAsync(AzureTableUser user, string email) => Task.Run(() => { user.Email = email; });

        public Task SetEmailConfirmedAsync(AzureTableUser user, bool confirmed) => Task.CompletedTask;

        public Task SetLockoutEnabledAsync(AzureTableUser user, bool enabled) => Task.CompletedTask;

        public Task SetLockoutEndDateAsync(AzureTableUser user, DateTimeOffset lockoutEnd) => Task.Run(() =>
        {
            user.LockOutEndDate = lockoutEnd;
        });

        public Task SetPasswordHashAsync(AzureTableUser user, string passwordHash) => Task.Run(() =>
        {
            user.Password = passwordHash;
        });


        public Task SetTwoFactorEnabledAsync(AzureTableUser user, bool enabled) => Task.CompletedTask;

        public async Task UpdateAsync(AzureTableUser user)
        {
            TableResult Result = await UserTable.ExecuteAsync(TableOperation.InsertOrReplace(user.ToEntity()));
        }
    }
}