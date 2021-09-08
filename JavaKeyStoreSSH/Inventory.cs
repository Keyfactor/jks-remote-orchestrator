// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Common.Enums;
using Keyfactor.Logging;

using Microsoft.Extensions.Logging;

namespace JavaKeyStoreSSH
{
    public class Inventory : IInventoryJobExtension
    {
        public string ExtensionName => "JKS-SSH";

        public JobResult ProcessJob(InventoryJobConfiguration config, SubmitInventoryUpdate submitInventory)
        {
            ILogger logger = LogHandler.GetClassLogger<Inventory>();
            logger.LogDebug($"Begin Inventory...");

            JKSStore jksStore = new JKSStore(config.CertificateStoreDetails.ClientMachine, config.ServerUsername, config.ServerPassword, config.CertificateStoreDetails.StorePath, config.CertificateStoreDetails.StorePassword);

            List<CurrentInventoryItem> inventoryItems = new List<CurrentInventoryItem>();
            try
            {
                ApplicationSettings.Initialize(this.GetType().Assembly.Location);

                jksStore.Initialize(string.Join(",", string.Empty));

                if (!jksStore.DoesStoreExist())
                    throw new JKSException($"Java Keystore {jksStore.StorePath}{jksStore.StoreFileName} cannot be found.");

                List<string> aliases = jksStore.GetAllStoreAliases();

                foreach (string alias in aliases)
                {
                    List<string> pemCertificates = jksStore.GetCertificateChainForAlias(alias);
                    if (pemCertificates.Count == 0)
                        continue;

                    inventoryItems.Add(new CurrentInventoryItem()
                    {
                        ItemStatus = OrchestratorInventoryItemStatus.Unknown,
                        Alias = alias,
                        PrivateKeyEntry = new X509Certificate2(Encoding.ASCII.GetBytes(pemCertificates[0])).HasPrivateKey,
                        UseChainLevel = pemCertificates.Count > 1,
                        Certificates = pemCertificates.ToArray()
                    });
                }  
            }
            catch (Exception ex)
            {
                return new JobResult() { Result = OrchestratorJobStatusJobResult.Failure, FailureMessage = ExceptionHandler.FlattenExceptionMessages(ex, $"Site {config.CertificateStoreDetails.StorePath} on server {config.CertificateStoreDetails.ClientMachine}:") };
            }
            finally
            {
                jksStore.Terminate();
            }

            try
            {
                submitInventory.Invoke(inventoryItems);
                return new JobResult() { Result = OrchestratorJobStatusJobResult.Success };
            }
            catch (Exception ex)
            {
                return new JobResult() { Result = OrchestratorJobStatusJobResult.Failure , FailureMessage = ExceptionHandler.FlattenExceptionMessages(ex, $"Site {config.CertificateStoreDetails.StorePath} on server {config.CertificateStoreDetails.ClientMachine}:") };
            }
        }
    }
}