// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.IO;
using System.Linq;

using Keyfactor.Logging;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Common.Enums;

using Microsoft.Extensions.Logging;

using Newtonsoft.Json;

using Org.BouncyCastle.Pkcs;

namespace Keyfactor.Extensions.Orchestrator.JavaKeyStoreSSH
{
    public class Management : IManagementJobExtension
    {
        public string ExtensionName => "JKS-SSH";

        public JobResult ProcessJob(ManagementJobConfiguration config)
        {
            ILogger logger = LogHandler.GetClassLogger<Management>();
            logger.LogDebug($"Begin Management...");

            JKSStore jksStore = new JKSStore(config.CertificateStoreDetails.ClientMachine, config.ServerUsername, config.ServerPassword, config.CertificateStoreDetails.StorePath, config.CertificateStoreDetails.StorePassword);
            
            string entryPassword = config.JobProperties == null || !config.JobProperties.ContainsKey("entryPassword") || string.IsNullOrEmpty((config.JobProperties["entryPassword"] ?? string.Empty).ToString()) ? string.Empty : config.JobProperties["entryPassword"].ToString();

            try
            {
                ApplicationSettings.Initialize(this.GetType().Assembly.Location);

                bool hasPassword = !string.IsNullOrEmpty(config.JobCertificate.PrivateKeyPassword);
                jksStore.Initialize(string.Join(",", string.Empty));

                switch (config.OperationType)
                {
                    case CertStoreOperationType.Add:
                        if (!jksStore.DoesStoreExist())
                            throw new JKSException($"Java Keystore {jksStore.StorePath}{jksStore.StoreFileName} cannot be found.");

                        byte[] certBytes = Convert.FromBase64String(config.JobCertificate.Contents);
                        MemoryStream stream = new MemoryStream(certBytes);
                        Pkcs12Store store;
                        string sourceAlias;

                        if (hasPassword)
                        {
                            store = new Pkcs12Store(stream, config.JobCertificate.PrivateKeyPassword.ToCharArray());
                            sourceAlias = store.Aliases.Cast<string>().FirstOrDefault(p => store.IsKeyEntry(p));
                            jksStore.AddPFXCertificateToStore(sourceAlias, config.JobCertificate.Alias, certBytes, config.JobCertificate.PrivateKeyPassword, entryPassword, config.Overwrite);
                        } 
                        else
                            jksStore.AddCertificateToStore(config.JobCertificate.Alias, certBytes, config.Overwrite);

                        break;

                    case CertStoreOperationType.Remove:
                        if (!jksStore.DoesStoreExist())
                            throw new JKSException($"Java Keystore {jksStore.StorePath}{jksStore.StoreFileName} cannot be found.");

                        jksStore.DeleteCertificateByAlias(config.JobCertificate.Alias);

                        break;

                    case CertStoreOperationType.Create:
                        logger.LogDebug($"Begin Create Operation for {config.CertificateStoreDetails.StorePath} on {config.CertificateStoreDetails.ClientMachine}.");
                        if (jksStore.DoesStoreExist())
                        {
                            logger.LogDebug($"Certificate store {config.CertificateStoreDetails.StorePath} on {config.CertificateStoreDetails.ClientMachine} already exists.  No action necessary.");
                            break;
                        }
                        jksStore.CreateCertificateStore(config.CertificateStoreDetails.StorePath, config.CertificateStoreDetails.StorePassword);
                        break; 
                    default:
                        return new JobResult() { Result = OrchestratorJobStatusJobResult.Failure, JobHistoryId = config.JobHistoryId, FailureMessage = $"Site {config.CertificateStoreDetails.StorePath} on server {config.CertificateStoreDetails.ClientMachine}: Unsupported operation: {config.OperationType.ToString()}" };
                }
            }
            catch (Exception ex)
            {
                return new JobResult() { Result = OrchestratorJobStatusJobResult.Failure, JobHistoryId = config.JobHistoryId, FailureMessage = ExceptionHandler.FlattenExceptionMessages(ex, $"Site {config.CertificateStoreDetails.StorePath} on server {config.CertificateStoreDetails.ClientMachine}:") };
            }
            finally
            {
                jksStore.Terminate();
            }

            return new JobResult() { Result = OrchestratorJobStatusJobResult.Success, JobHistoryId = config.JobHistoryId };
        }
    }
}