using HelloStorageIdentity.Entities;
using Microsoft.AspNet.Identity;
using Microsoft.WindowsAzure.Storage.Table;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace HelloStorageIdentity.Models
{
    public class AzureTableUser : IUser
    {
        public string Id => UserName;

        public string UserName { get; set; }
        public string Password { get; set; }
        public string Email { get; set; }
        public int FailedLogIns { get; set; }
        public DateTimeOffset LockOutEndDate { get; set; }
        public string PhoneNumber { get; set; }
        public IList<string> Roles { get; set; }
        public IList<string> Claims { get; set; }

    }

    public static class AzureTableUserExtension
    {
        public static UserDataEntity ToEntity(this AzureTableUser User)
        {
            return new UserDataEntity()
            {
                PartitionKey = "UserData",
                RowKey = User.UserName,
                Password = User.Password,
                Email = User.Email,
                FailedLogIns = User.FailedLogIns,
                LockOutEndDate = User.LockOutEndDate,
                PhoneNumber = User.PhoneNumber,
                Roles = string.Join("|", User.Roles),
                Claims = string.Join("|", User.Claims)
            };
        }
    }
}