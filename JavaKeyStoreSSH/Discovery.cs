// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;

using Newtonsoft.Json;

using Keyfactor.Logging;
using Keyfactor.Orchestrators.Extensions;
using Keyfactor.Orchestrators.Common.Enums;

using Microsoft.Extensions.Logging;

namespace JavaKeyStoreSSH
{
    public class Discovery : IDiscoveryJobExtension
    {
        public string ExtensionName => "JKS-SSH";

        public JobResult ProcessJob(DiscoveryJobConfiguration config, SubmitDiscoveryUpdate submitDiscovery)
        {
            ILogger logger = LogHandler.GetClassLogger<Inventory>();
            logger.LogDebug($"Begin Discovery...");

            List<string> locations = new List<string>();
            string server = string.Empty;
            
            string[] directoriesToSearch = config.JobProperties["dirs"].ToString().Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
            string[] extensionsToSearch = config.JobProperties["extensions"].ToString().Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
            string[] ignoredDirs = config.JobProperties["ignoreddirs"].ToString().Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
            string[] filesTosearch = config.JobProperties["patterns"].ToString().Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);

            JKSStore jksStore = new JKSStore(config.ClientMachine, config.ServerUsername, config.ServerPassword, directoriesToSearch[0].Substring(0, 1) == "/" ? JKSStore.ServerTypeEnum.Linux : JKSStore.ServerTypeEnum.Windows);

            try
            {
                ApplicationSettings.Initialize(this.GetType().Assembly.Location);

                if (directoriesToSearch.Length == 0)
                    throw new JKSException("Blank or missing search directories for Discovery.");
                if (extensionsToSearch.Length == 0)
                    throw new JKSException("Blank or missing search extensions for Discovery.");
                if (filesTosearch.Length == 0)
                    filesTosearch = new string[] { "*" };

                jksStore.Initialize(string.Join(",", extensionsToSearch));

                locations = jksStore.FindStores(directoriesToSearch, extensionsToSearch, filesTosearch);
                foreach (string ignoredDir in ignoredDirs)
                    locations = locations.Where(p => !p.StartsWith(ignoredDir)).ToList();

                if (jksStore.ServerType == JKSStore.ServerTypeEnum.Linux)
                    locations = locations.Where(p => jksStore.IsValidStore(p)).ToList();
            }
            catch (Exception ex)
            {
                return new JobResult() { Result = OrchestratorJobStatusJobResult.Failure, FailureMessage = ExceptionHandler.FlattenExceptionMessages(ex, $"Server {config.ClientMachine}:") };
            }
            finally
            {
                jksStore.Terminate();
            }

            try
            {
                submitDiscovery.Invoke(locations);
                return new JobResult() { Result = OrchestratorJobStatusJobResult.Success };
            }
            catch (Exception ex)
            {
                return new JobResult() { Result = OrchestratorJobStatusJobResult.Failure, FailureMessage = ExceptionHandler.FlattenExceptionMessages(ex, $"Server {config.ClientMachine}:") };
            }
        }
    }
}