﻿// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Text;

namespace JavaKeyStoreSSH.RemoteHandlers
{
    class WinRMHandler : BaseRemoteHandler
    {
        private const string IGNORED_ERROR1 = "importing keystore";
        private const string IGNORED_ERROR2 = "warning:";
        private const string IGNORED_ERROR3 = "certificate was added to keystore";

        private Runspace runspace { get; set; }

        internal WinRMHandler(string server)
        {
            Server = server;
        }

        public override void Initialize()
        {
            try
            {
                WSManConnectionInfo connectionInfo = new WSManConnectionInfo(new System.Uri($"{Server}/wsman"));
                if (ApplicationSettings.UseNegotiateAuth)
                {
                    connectionInfo.AuthenticationMechanism = AuthenticationMechanism.Negotiate;
                }
                Logger.Trace($"WinRM Authentication Mechanism: {Enum.GetName(typeof(AuthenticationMechanism), connectionInfo.AuthenticationMechanism)}");
                runspace = RunspaceFactory.CreateRunspace(connectionInfo);
                runspace.Open();
            }

            catch (Exception ex)
            {
                Logger.Debug($"Exception during Initialize...{ExceptionHandler.FlattenExceptionMessages(ex, ex.Message)}");
                throw ex;
            }
        }

        public override void Terminate()
        {
            runspace.Close();
            runspace.Dispose();
        }

        public override string RunCommand(string commandText, object[] parameters, bool withSudo, string[] passwordsToMaskInLog)
        {
            Logger.Debug($"RunCommand: {Server}");

            try
            {
                using (PowerShell ps = PowerShell.Create())
                {
                    ps.Runspace = runspace;

                    if (commandText.ToLower().IndexOf("keytool ") > -1)
                    {
                        commandText = ($"& '{commandText}").Replace("keytool", "keytool'");
                        commandText = "echo '' | " + commandText;
                    }
                    ps.AddScript(commandText);

                    string displayCommand = commandText;
                    if (passwordsToMaskInLog != null)
                    {
                        foreach (string password in passwordsToMaskInLog)
                            displayCommand = displayCommand.Replace(password, PASSWORD_MASK_VALUE);
                    }

                    if (parameters != null)
                    {
                        foreach(object parameter in parameters)
                            ps.AddArgument(parameter);
                    }

                    Logger.Debug($"RunCommand: {displayCommand}");
                    string result = FormatResult(ps.Invoke(parameters));

                    if (ps.HadErrors)
                    {
                        string errors = string.Empty;
                        System.Collections.ObjectModel.Collection<ErrorRecord> errorRecords = ps.Streams.Error.ReadAll();
                        foreach (ErrorRecord errorRecord in errorRecords)
                        {
                            string error = errorRecord.ToString();
                            if (error.ToLower().StartsWith(IGNORED_ERROR1) ||
                                error.ToLower().Contains(IGNORED_ERROR2) ||
                                error.ToLower().Contains(IGNORED_ERROR3))
                            {
                                errors = null;
                                break;
                            }
                                    
                            errors += (error + "   ");
                        }

                        if (!string.IsNullOrEmpty(errors))
                            throw new ApplicationException(errors);
                    }
                    else
                        Logger.Debug($"WinRM Results: {displayCommand}::: {result}");

                    if (result.ToLower().Contains(KEYTOOL_ERROR))
                        throw new ApplicationException(result);

                    return result;
                }
            }
            catch (Exception ex)
            {
                Logger.Debug($"Exception during RunCommand...{ExceptionHandler.FlattenExceptionMessages(ex, ex.Message)}");
                throw ex;
            }
        }

        public override void UploadCertificateFile(string path, string fileName, byte[] certBytes)
        {
            Logger.Debug($"UploadCertificateFile: {path} {fileName}");

            string scriptBlock = $@"
                                    param($contents)
                                
                                    Set-Content '{path + fileName}' -Encoding Byte -Value $contents
                                ";

            object[] arguments = new object[] { certBytes };

            RunCommand(scriptBlock, arguments, false, null);
        }

        public override void RemoveCertificateFile(string path, string fileName)
        {
            Logger.Debug($"RemoveCertificateFile: {path} {fileName}");

            RunCommand($"rm '{path}{fileName}'", null, false, null);
        }

        public override bool DoesStoreExist(string path, string fileName)
        {
            Logger.Debug($"DoesStoreExist: {path} {fileName}");

            string NOT_EXISTS = "file not found";
            string result = RunCommand($"dir '{path}{fileName}'", null, false, null);

            return !result.ToLower().Contains(NOT_EXISTS);
        }

        private string FormatResult(ICollection<PSObject> results)
        {
            StringBuilder rtn = new StringBuilder();

            foreach (PSObject resultLine in results)
            {
                if (resultLine != null)
                    rtn.Append(resultLine.ToString() + System.Environment.NewLine);
            }

            return rtn.ToString();
        }

        private string FormatFTPPath(string path)
        {
            return path.Substring(0, 1) == @"/" ? path : @"/" + path.Replace("\\", "/");
        }
    }
}
