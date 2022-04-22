// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System.IO;

using Newtonsoft.Json;

namespace Keyfactor.Extensions.Orchestrator.JavaKeyStoreSSH
{
    class ApplicationSettings
    {
        public static bool UseSudo { get; set; }
        public static bool UsePrerunScript { get; set; }
        public static string PreRunScript { get; set; }
        public static string PreRunScriptDestinationPath { get; set; }
        public static string Script { get; set; }
        public static bool UseSeparateUploadFilePath { get; set; }
        public static string SeparateUploadFilePath { get; set; }
        public static bool FindKeytoolPathOnWindows { get; set; }
        public static bool UseNegotiateAuth { get; set; }
        public static bool UseSCP { get; set; }
        public static string DefaultLinuxPermissionsOnStoreCreation { get; set; }

        private const string DEFAULT_LINUX_PERMISSION_SETTING = "600";

        public static void Initialize(string currLocation)
        {
            string configContents = string.Empty;
            string currDir = Path.GetDirectoryName(currLocation);

            if (!File.Exists($@"{currDir}\config.json"))
                throw new JKSException($"config.json file does not exist in {currDir}");

            using (StreamReader sr = new StreamReader($@"{currDir}\config.json"))
            {
                configContents = sr.ReadToEnd();
            }

            dynamic jsonContents = JsonConvert.DeserializeObject(configContents);

            DefaultLinuxPermissionsOnStoreCreation = jsonContents.DefaultLinuxPermissionsOnStoreCreation == null ? DEFAULT_LINUX_PERMISSION_SETTING : jsonContents.DefaultLinuxPermissionsOnStoreCreation.Value;
            
            ValidateConfig(jsonContents);

            UseSudo = jsonContents.UseSudo.Value.Equals("Y", System.StringComparison.OrdinalIgnoreCase);

            UsePrerunScript = jsonContents.UsePreRunScript.Value.Equals("Y", System.StringComparison.OrdinalIgnoreCase);
            PreRunScript = jsonContents.PreRunScript.Value;
            if (UsePrerunScript)
            {
                using (StreamReader sr = new StreamReader($@"{currDir}\{PreRunScript}"))
                {
                    Script = sr.ReadToEnd();
                }
            }

            PreRunScriptDestinationPath = AddTrailingSlash(jsonContents.PreRunScriptDestinationPath.Value);
            UseSeparateUploadFilePath = jsonContents.UseSeparateUploadFilePath.Value.Equals("Y", System.StringComparison.OrdinalIgnoreCase);
            SeparateUploadFilePath = AddTrailingSlash(jsonContents.SeparateUploadFilePath.Value);
            FindKeytoolPathOnWindows = jsonContents.FindKeytoolPathOnWindows.Value.Equals("Y", System.StringComparison.OrdinalIgnoreCase);
            UseNegotiateAuth = jsonContents.UseNegotiateAuth.Value.Equals("Y", System.StringComparison.OrdinalIgnoreCase);
            UseSCP = jsonContents.UseSCP == null || !jsonContents.UseSCP.Value.Equals("Y", System.StringComparison.OrdinalIgnoreCase) ? false : true;
        }

        private static string AddTrailingSlash(string path)
        {
            return path.Substring(path.Length - 1, 1) == @"/" ? path : path += @"/";
        }

        private static void ValidateConfig(dynamic jsonContents)
        {
            string errors = string.Empty;

            if (jsonContents.UseSudo == null)
                errors += "UseSudo, ";
            if (jsonContents.UsePreRunScript == null)
                errors += "UsePreRunScript, ";
            if (jsonContents.PreRunScript == null)
                errors += "PreRunScript, ";
            if (jsonContents.PreRunScriptDestinationPath == null)
                errors += "PreRunScriptDestinationPath, ";
            if (jsonContents.UseSeparateUploadFilePath == null)
                errors += "UseSeparateUploadFilePath, ";
            if (jsonContents.SeparateUploadFilePath == null)
                errors += "SeparateUploadFilePath, ";
            if (jsonContents.FindKeytoolPathOnWindows == null)
                errors += "FindKeytoolPathOnWindows, ";
            if (jsonContents.UseNegotiateAuth == null)
                errors += "UseNegotiateAuth, ";

            if (errors.Length > 0)
                throw new JKSException($"The following configuration items are missing from the config.json file: {errors.Substring(0, errors.Length-2)}");
        }
    }
}

