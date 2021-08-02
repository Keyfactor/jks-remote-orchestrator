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

using Newtonsoft.Json.Linq;

using Keyfactor.Platform.Extensions.Agents;
using Keyfactor.Platform.Extensions.Agents.Enums;
using Keyfactor.Platform.Extensions.Agents.Delegates;
using Keyfactor.Platform.Extensions.Agents.Interfaces;

using CSS.Common.Logging;


using Microsoft.Web.Administration;

namespace JavaKeyStoreSSH
{
    public class Inventory : LoggingClientBase, IAgentJobExtension
    {
        public string GetJobClass()
        {
            return "Inventory";
        }

        public string GetStoreType()
        {
            return "JKS-SSH";
        }

        public AnyJobCompleteInfo processJob(AnyJobConfigInfo config, SubmitInventoryUpdate submitInventory, SubmitEnrollmentRequest submitEnrollmentRequest, SubmitDiscoveryResults sdr)
        {
            Logger.Debug($"Begin Inventory...");

            JKSStore jksStore = new JKSStore(config.Store.ClientMachine, config.Server.Username, config.Server.Password, config.Store.StorePath, config.Store.StorePassword);

            List<AgentCertStoreInventoryItem> inventoryItems = new List<AgentCertStoreInventoryItem>();
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

                    inventoryItems.Add(new AgentCertStoreInventoryItem()
                    {
                        ItemStatus = AgentInventoryItemStatus.Unknown,
                        Alias = alias,
                        PrivateKeyEntry = new X509Certificate2(Encoding.ASCII.GetBytes(pemCertificates[0])).HasPrivateKey,
                        UseChainLevel = pemCertificates.Count > 1,
                        Certificates = pemCertificates.ToArray()
                    });
                }  
            }
            catch (Exception ex)
            {
                return new AnyJobCompleteInfo() { Status = 4, Message = ExceptionHandler.FlattenExceptionMessages(ex, $"Site {config.Store.StorePath} on server {config.Store.ClientMachine}:") };
            }
            finally
            {
                jksStore.Terminate();
            }

            try
            {
                submitInventory.Invoke(inventoryItems);
                return new AnyJobCompleteInfo() { Status = 2, Message = "Successful" };
            }
            catch (Exception ex)
            {
                return new AnyJobCompleteInfo() { Status = 4, Message = ExceptionHandler.FlattenExceptionMessages(ex, $"Site {config.Store.StorePath} on server {config.Store.ClientMachine}:") };
            }
        }
    }
}