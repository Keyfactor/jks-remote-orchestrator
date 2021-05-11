using System.IO;
using System.Text;

using Newtonsoft.Json;

namespace JavaKeyStoreSSH
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

            if (errors.Length > 0)
                throw new JKSException($"The following configuration items are missing from the config.json file: {errors.Substring(0, errors.Length-2)}");
        }
    }
}

