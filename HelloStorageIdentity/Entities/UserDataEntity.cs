using HelloStorageIdentity.Models;
using Microsoft.WindowsAzure.Storage.Table;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace HelloStorageIdentity.Entities
{
    public class UserDataEntity : TableEntity
    {
        public string Password { get; set; }
        public string Email { get; set; }
        public int FailedLogIns { get; set; }
        public DateTimeOffset LockOutEndDate { get; set; }
        public string PhoneNumber { get; set; }
        public string Roles { get; set; } // admin|mod
        public string Claims { get; set; } // claim1|claim2
    }

    public static class UserDataEntityExtension
    {
        public static AzureTableUser ToUser(this UserDataEntity Entity)
        {
            return new AzureTableUser()
            {
                UserName = Entity.RowKey,
                Password = Entity.Password,
                FailedLogIns = Entity.FailedLogIns,
                LockOutEndDate = Entity.LockOutEndDate,
                PhoneNumber = Entity.PhoneNumber,
                Email = Entity.Email,
                Roles = Entity.Roles.Split('|'),
                Claims = Entity.Claims.Split('|')
            };
        }
    }
}