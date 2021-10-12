// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using Newtonsoft.Json;

using Keyfactor.Extensions.Orchestrator.JavaKeyStoreSSH.RemoteHandlers;
//using Keyfactor.Extensions.Pam.Utilities;

namespace Keyfactor.Extensions.Orchestrator.JavaKeyStoreSSH
{
    internal class JKSStore
    {
        private const string NO_EXTENSION = "noext";
        private const string FULL_SCAN = "fullscan";

        const string BEG_DELIM = "-----BEGIN CERTIFICATE-----";
        const string END_DELIM = "-----END CERTIFICATE-----";
        const string ALIAS_DELIM = "Alias name: ";
        const string FILE_NAME_REPL = "||FILE_NAME_HERE||";

        static Mutex mutex = new Mutex(false, "ModifyStore");

        internal enum ServerTypeEnum
        {
            Linux,
            Windows
        }

        internal string Server { get; set; }
        internal string ServerId { get; set; }
        internal string ServerPassword { get; set; }
        internal string StorePath { get; set; }
        internal string StoreFileName { get; set; }
        internal string StorePassword { get; set; }
        internal IRemoteHandler SSH { get; set; }
        internal ServerTypeEnum ServerType { get; set; }
        internal string KeytoolPath { get; set; }
        internal List<string> DiscoveredStores { get; set; }

        internal string UploadFilePath { get; set; }


        internal JKSStore(string server, string serverId, string serverPassword, string storeFileAndPath, string storePassword)
        {
            Server = server;
            SplitStorePathFile(storeFileAndPath);
            ServerId = serverId;
            ServerPassword = serverPassword ?? string.Empty;
            StorePassword = storePassword;
            ServerType = StorePath.Substring(0, 1) == "/" ? ServerTypeEnum.Linux : ServerTypeEnum.Windows;
            UploadFilePath = ApplicationSettings.UseSeparateUploadFilePath && ServerType == ServerTypeEnum.Linux ? ApplicationSettings.SeparateUploadFilePath : StorePath;
        }

        internal JKSStore(string server, string serverId, string serverPassword, ServerTypeEnum serverType)
        {
            Server = server;
            ServerId = serverId;
            ServerPassword = serverPassword ?? string.Empty;
            ServerType = serverType;
        }

        internal void Initialize(string extensions)
        {
            if (ServerType == ServerTypeEnum.Linux)
                SSH = new SSHHandler(Server, ServerId, ServerPassword);
                //SSH = new SSHHandler(Server, ServerId, PamUtility.ResolvePassword(ServerPassword));
            else
                SSH = new WinRMHandler(Server);

            try
            {
                SSH.Initialize();
            }
            catch (Exception ex)
            {
                throw new JKSException("Error attempting to connect to the remote server.", ex);
            }

            if (!ApplicationSettings.UsePrerunScript && !IsKeytoolInstalled())
                throw new JKSException($"Java is either not installed on the server or is not in the $PATH environment variable for store path={StorePath}, file name={StoreFileName}.");

            if (ApplicationSettings.UsePrerunScript && ServerType == ServerTypeEnum.Linux)
            {
                string cmdFileName = Guid.NewGuid().ToString().Replace("-",string.Empty);
                string cmdFileAndPath = ApplicationSettings.PreRunScriptDestinationPath + cmdFileName;

                try
                {
                    try
                    {
                        SSH.UploadCertificateFile(ApplicationSettings.PreRunScriptDestinationPath, cmdFileName, System.Text.Encoding.ASCII.GetBytes(ApplicationSettings.Script));
                    }
                    catch (Exception ex)
                    {
                        throw new JKSException("Error attempting to upload certificate file to the remote server. ", ex);
                    }
                    SSH.RunCommand($"dos2unix {cmdFileAndPath}", null, ApplicationSettings.UseSudo, null);
                    SSH.RunCommand($"chmod +x {cmdFileAndPath}", null, ApplicationSettings.UseSudo, null);

                    if (!string.IsNullOrEmpty(extensions))
                        cmdFileAndPath += (" '" + extensions + "'");

                    string cmdResult = SSH.RunCommand(cmdFileAndPath, null, ApplicationSettings.UseSudo, null);
                    dynamic result = JsonConvert.DeserializeObject(cmdResult);

                    KeytoolPath = result.KeyToolPath;
                    if (!string.IsNullOrEmpty(extensions))
                    {
                        try
                        {
                            DiscoveredStores = result.DiscoveredFiles.ToObject<List<string>>();
                        }
                        catch (Microsoft.CSharp.RuntimeBinder.RuntimeBinderException)
                        {
                            DiscoveredStores = null;
                        }
                    }
                }

                finally
                {
                    try
                    {
                        SSH.RemoveCertificateFile(ApplicationSettings.PreRunScriptDestinationPath, cmdFileName);
                    }
                    catch (Exception) { }
                }
            }

            if (ApplicationSettings.FindKeytoolPathOnWindows && ServerType == ServerTypeEnum.Windows)
            {
                string[] paths = GetAvailablePaths();
                foreach(string path in paths)
                {
                    string cmd = $"(Get-ChildItem -Path {FormatPath(path)} -Recurse -ErrorAction SilentlyContinue -Include keytool.exe).fullname";
                    string result = SSH.RunCommand(cmd, null, ApplicationSettings.UseSudo, null);

                    if (!string.IsNullOrEmpty(result))
                    {
                        List<string> results = result.Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries).ToList();
                        KeytoolPath = FormatPath(results[0].Substring(0, results[0].LastIndexOf(@"\")));

                        break;
                    }
                }
            }
        }

        internal void Terminate()
        {
            if (SSH != null)
                SSH.Terminate();
        }

        internal bool DoesStoreExist()
        {
            return SSH.DoesStoreExist(StorePath, StoreFileName);
        }

        internal bool IsValidStore(string path)
        {
            string keyToolCommand = $"{KeytoolPath}keytool -v -list -keystore '{path}'";
            string result = SSH.RunCommand(keyToolCommand, null, ApplicationSettings.UseSudo, null);
            return result.IndexOf(ALIAS_DELIM) > -1;
        }

        internal List<string> FindStores(string[] paths, string[] extensions, string[] files)
        {
            if (DiscoveredStores != null)
                return DiscoveredStores;

            return ServerType == ServerTypeEnum.Linux ? FindStoresLinux(paths, extensions, files) : FindStoresWindows(paths, extensions, files);
        }

        internal bool DoesCertificateAliasExist(string alias)
        {
            string keyToolCommand = $"{KeytoolPath}keytool -list -keystore '{StorePath + StoreFileName}' -alias '{alias}' {FormatStorePassword()}";
            string result = SSH.RunCommand(keyToolCommand, null, ServerType == ServerTypeEnum.Linux && ApplicationSettings.UseSudo, StorePassword == null ? null : new string[] { StorePassword });
            return !result.Contains("not exist");
        }

        internal List<string> GetAllStoreAliases()
        {
            string keyToolCommand = $"{KeytoolPath}keytool -list -v -keystore '{StorePath + StoreFileName}' {FormatStorePassword()}";
            string result = SSH.RunCommand(keyToolCommand, null, ServerType == ServerTypeEnum.Linux && ApplicationSettings.UseSudo, StorePassword == null ? null : new string[] { StorePassword }).Replace("\r", string.Empty);

            int aliasIdx = result.IndexOf(ALIAS_DELIM);
            if (aliasIdx == -1)
                return new List<string>();

            result = result.Substring(aliasIdx);

            string[] aliases = result.Split(new string[] { ALIAS_DELIM }, StringSplitOptions.RemoveEmptyEntries);
            for (int i = 0; i < aliases.Length; i++)
                aliases[i] = aliases[i].Substring(0, aliases[i].IndexOf("\n"));

            return aliases.ToList();
        }

        internal List<string> GetCertificateChainForAlias(string alias)
        {
            List<string> certChain = new List<string>();
            string keyToolCommand = $"{KeytoolPath}keytool -list -rfc -keystore '{StorePath + StoreFileName}' {FormatStorePassword()} -alias '{alias}'";
            string result = SSH.RunCommand(keyToolCommand, null, ServerType == ServerTypeEnum.Linux && ApplicationSettings.UseSudo, StorePassword == null ? null : new string[] { StorePassword });

            if (!result.Contains(BEG_DELIM))
                return certChain;

            int chainLength = GetChainLength(result);
            for (int i = 0; i < chainLength; i++)
            {
                certChain.Add(result.Substring(result.IndexOf(BEG_DELIM), result.IndexOf(END_DELIM) - result.IndexOf(BEG_DELIM) + END_DELIM.Length));
                result = result.Substring(result.IndexOf(END_DELIM) + END_DELIM.Length);
            }

            return certChain;
        }

        internal void DeleteCertificateByAlias(string alias)
        {
            string keyToolCommand = $"{KeytoolPath}keytool -delete -alias '{alias}' -keystore '{StorePath + StoreFileName}' {FormatStorePassword()}";
            
            try
            {
                mutex.WaitOne();
                string result = SSH.RunCommand(keyToolCommand, null, ServerType == ServerTypeEnum.Linux && ApplicationSettings.UseSudo, StorePassword == null ? null : new string[] { StorePassword });
            }
            catch (Exception ex)
            {
                throw new JKSException($"Error attempting to remove certficate for store path={StorePath}, file name={StoreFileName}.", ex);
            }
            finally
            {
                mutex.ReleaseMutex();
            }
        }

        internal void CreateCertificateStore(string storePath, string storePassword)
        {
            //No option to create a blank store.  Generate a self signed cert with some default and limited validity.
            string keyToolCommand = $"{KeytoolPath}keytool -genkeypair -keystore {storePath} -storepass {storePassword} -dname \"cn=New Certificate Store\" -validity 1 -alias \"NewCertStore\"";
            SSH.RunCommand(keyToolCommand, null, ServerType == ServerTypeEnum.Linux && ApplicationSettings.UseSudo, StorePassword == null ? null : new string[] { StorePassword });
        }

        internal void AddCertificateToStore(string alias, byte[] certBytes, bool overwrite)
        {
            string keyToolCommand = $"{KeytoolPath}keytool -import -alias '{alias}' -keystore '{StorePath + StoreFileName}' -file '{UploadFilePath}{FILE_NAME_REPL}.pem' -deststorepass '{StorePassword}' -noprompt";
            AddEntry(keyToolCommand, alias, certBytes, null, overwrite);
        }

        internal void AddPFXCertificateToStore(string sourceAlias, string destAlias, byte[] certBytes, string pfxPassword, string entryPassword, bool overwrite)
        {
            string keyToolCommand = $"{KeytoolPath}keytool -importkeystore -srckeystore '{UploadFilePath}{FILE_NAME_REPL}.p12' -srcstoretype PKCS12 -srcstorepass '{pfxPassword}' -srcalias '{sourceAlias}' " +
                $"-destkeystore '{StorePath + StoreFileName}' -destalias '{destAlias}' -deststoretype JKS -destkeypass '{(string.IsNullOrEmpty(entryPassword) ? StorePassword : entryPassword)}' -deststorepass '{StorePassword}' -noprompt";
            AddEntry(keyToolCommand, destAlias, certBytes, pfxPassword, overwrite);
        }

        private bool IsKeytoolInstalled()
        {
            string keyToolCommand = ServerType == ServerTypeEnum.Linux ? $"which keytool" : "java -version 2>&1";
            string result = SSH.RunCommand(keyToolCommand, null, ServerType == ServerTypeEnum.Linux && ApplicationSettings.UseSudo, null);
            return !(string.IsNullOrEmpty(result));
        }

        private List<string> FindStoresLinux(string[] paths, string[] extensions, string[] fileNames)
        {
            try
            {
                string concatPaths = string.Join(" ", paths);
                string command = $"find {concatPaths} ";

                foreach (string extension in extensions)
                {
                    foreach (string fileName in fileNames)
                    {
                        command += (command.IndexOf("-iname") == -1 ? string.Empty : "-or ");
                        command += $"-iname '{fileName.Trim()}";
                        if (extension.ToLower() == NO_EXTENSION)
                            command += $"' ! -iname '*.*' ";
                        else
                            command += $".{extension.Trim()}' ";
                    }
                }

                string result = string.Empty;
                if (extensions.Any(p => p.ToLower() != NO_EXTENSION))
                    result = SSH.RunCommand(command, null, ApplicationSettings.UseSudo, null);

                return (result.Split(new char[] { '\n' }, StringSplitOptions.RemoveEmptyEntries)).ToList();
            }
            catch (Exception ex)
            {
                throw new JKSException($"Error attempting to find certificate stores for path={string.Join(" ", paths)}.", ex);
            }
        }

        private List<string> FindStoresWindows(string[] paths, string[] extensions, string[] fileNames)
        {
            List<string> results = new List<string>();
            StringBuilder concatFileNames = new StringBuilder();

            if (paths[0] == FULL_SCAN)
            {
                paths = GetAvailablePaths();
                for (int i = 0; i < paths.Length; i++)
                    paths[i] += "/";
            }

            foreach (string path in paths)
            {
                foreach (string extension in extensions)
                {
                    foreach (string fileName in fileNames)
                        concatFileNames.Append($",{fileName}.{extension}");
                }

                string command = $"(Get-ChildItem -Path {FormatPath(path)} -Recurse -ErrorAction SilentlyContinue -Include {concatFileNames.ToString().Substring(1)}).fullname";
                string result = SSH.RunCommand(command, null, false, null);
                results.AddRange(result.Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries).ToList());
            }

            return results;
        }

        private string[] GetAvailablePaths()
        {
            string command = @"Get-WmiObject Win32_Logicaldisk -Filter ""DriveType = '3'"" | % {$_.DeviceId}";
            string result = SSH.RunCommand(command, null, false, null);
            return result.Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);
        }

        private void AddEntry(string command, string alias, byte[] certBytes, string pfxPassword, bool overwrite)
        {
            string fileSuffix = string.IsNullOrEmpty(pfxPassword) ? ".pem" : ".p12";
            string fileName = Guid.NewGuid().ToString().Replace("-", string.Empty);
            command = command.Replace(FILE_NAME_REPL, fileName);

            try
            {
                mutex.WaitOne();
                if (DoesCertificateAliasExist(alias))
                {
                    if (overwrite)
                        DeleteCertificateByAlias(alias);
                    else
                        throw new JKSException($"Alias already exists in certificate store.");
                }

                try
                {
                    SSH.UploadCertificateFile(UploadFilePath, $"{fileName}{fileSuffix}", certBytes);
                }
                catch (Exception ex)
                {
                    throw new JKSException("Error attempting to upload certificate file to the remote server. ", ex);
                }

            SSH.RunCommand(command, null, ServerType == ServerTypeEnum.Linux && ApplicationSettings.UseSudo, StorePassword == null ? null : new string[] { StorePassword });
            }
            catch (Exception ex)
            {
                throw new JKSException($"Error attempting to add certficate for store path={StorePath}, file name={StoreFileName}.", ex);
            }
            finally
            {
                try
                {
                    SSH.RemoveCertificateFile(StorePath, $"{fileName}{fileSuffix}");
                }
                catch (Exception) { }
                finally
                {
                    mutex.ReleaseMutex();
                }
            }
        }

        private void SplitStorePathFile(string pathFileName)
        {
            try
            {
                string workingPathFileName = pathFileName.Replace(@"\", @"/");
                int separatorIndex = workingPathFileName.LastIndexOf(@"/");
                StoreFileName = pathFileName.Substring(separatorIndex + 1);
                StorePath = pathFileName.Substring(0, separatorIndex + 1);
            }
            catch (Exception ex)
            {
                throw new JKSException($"Error attempting to parse certficate store path={StorePath}, file name={StoreFileName}.", ex);
            }
        }

        private int GetChainLength(string certificates)
        {
            int count = 0;
            int i = 0;
            while ((i = certificates.IndexOf(BEG_DELIM, i)) != -1)
            {
                i += BEG_DELIM.Length;
                count++;
            }
            return count;
        }

        private string FormatStorePassword()
        {
            return (!string.IsNullOrEmpty(StorePassword) ? $"-storepass '{StorePassword}'" : string.Empty);
        }

        private string FormatPath(string path)
        {
            return path + (path.Substring(path.Length - 1) == @"\" ? string.Empty : @"\");
        }
    }

    class JKSException : ApplicationException
    {
        public JKSException(string message) : base(message)
        { }

        public JKSException(string message, Exception ex) : base(message, ex)
        { }
    }
}