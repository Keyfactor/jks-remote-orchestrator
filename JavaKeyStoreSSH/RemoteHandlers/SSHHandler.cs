// Copyright 2021 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

using Renci.SshNet;

using Microsoft.Extensions.Logging;

namespace Keyfactor.Extensions.Orchestrator.JavaKeyStoreSSH.RemoteHandlers
{
    class SSHHandler : BaseRemoteHandler
    {
        private ConnectionInfo Connection { get; set; }

        private SshClient sshClient;

        internal SSHHandler(string server, string serverLogin, string serverPassword)
        {
            Server = server;

            List<AuthenticationMethod> authenticationMethods = new List<AuthenticationMethod>();
            if (serverPassword.Length < PASSWORD_LENGTH_MAX)
                authenticationMethods.Add(new PasswordAuthenticationMethod(serverLogin, serverPassword));
            else
                authenticationMethods.Add(new PrivateKeyAuthenticationMethod(serverLogin, new PrivateKeyFile[] { new PrivateKeyFile(new MemoryStream(Encoding.ASCII.GetBytes(ReplaceSpacesWithLF(serverPassword)))) }));

            Connection = new ConnectionInfo(server, serverLogin, authenticationMethods.ToArray());
        }

        public override void Initialize()
        {
            sshClient = new SshClient(Connection);
            sshClient.Connect();
        }

        public override void Terminate()
        {
            sshClient.Disconnect();
            sshClient.Dispose();
        }

        public override string RunCommand(string commandText, object[] arguments, bool withSudo, string[] passwordsToMaskInLog)
        {
            _logger.LogDebug($"RunCommand: {Server}");

            string sudo = $"sudo -i -S ";
            string echo = $"echo -e '\n' | ";

            try
            {
                if (withSudo)
                    commandText = sudo + commandText;

                commandText = echo + commandText;

                string displayCommand = commandText;
                if (passwordsToMaskInLog != null)
                {
                    foreach (string password in passwordsToMaskInLog)
                        displayCommand = displayCommand.Replace(password, PASSWORD_MASK_VALUE);
                }

                using (SshCommand command = sshClient.CreateCommand($"{commandText}"))
                {
                    _logger.LogDebug($"RunCommand: {displayCommand}");
                    command.Execute();
                    _logger.LogDebug($"SSH Results: {displayCommand}::: {command.Result}::: {command.Error}");

                    if (command.Result.ToLower().Contains(KEYTOOL_ERROR))
                        throw new ApplicationException(command.Result);
                    
                    return string.IsNullOrEmpty(command.Result) && !string.IsNullOrEmpty(command.Error) ? command.Error : command.Result;
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug($"Exception during RunCommand...{ExceptionHandler.FlattenExceptionMessages(ex, ex.Message)}");
                throw ex;
            }
        }

        public override void UploadCertificateFile(string path, string fileName, byte[] certBytes)
        {
            _logger.LogDebug($"UploadCertificateFile: {path} {fileName}");

            try
            {
                if (ApplicationSettings.UseSCP)
                {
                    using (ScpClient client = new ScpClient(Connection))
                    {
                        try
                        {
                            client.Connect();

                            using (MemoryStream stream = new MemoryStream(certBytes))
                            {
                                client.Upload(stream, FormatFTPPath(path + $"/{fileName}"));
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogDebug("Exception during SCP upload...");
                            _logger.LogDebug($"Upload Exception: {ExceptionHandler.FlattenExceptionMessages(ex, ex.Message)}");
                            throw ex;
                        }
                        finally
                        {
                            client.Disconnect();
                        }
                    }
                }
                else
                {
                    using (SftpClient client = new SftpClient(Connection))
                    {
                        try
                        {
                            client.Connect();
                            client.ChangeDirectory(FormatFTPPath(path));

                            using (MemoryStream stream = new MemoryStream(certBytes))
                            {
                                client.UploadFile(stream, fileName);
                            }
                        }
                        catch (Exception ex)
                        {
                            _logger.LogDebug("Exception during SFTP upload...");
                            _logger.LogDebug($"Upload Exception: {ExceptionHandler.FlattenExceptionMessages(ex, ex.Message)}");
                            throw ex;
                        }
                        finally
                        {
                            client.Disconnect();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug($"Exception making SFTP connection - {ex.Message}");
                throw ex;
            }
        }

        public override void RemoveCertificateFile(string path, string fileName)
        {
            _logger.LogDebug($"RemoveCertificateFile: {path} {fileName}");

            RunCommand($"rm {path}{fileName}", null, ApplicationSettings.UseSudo, null);
        }

        public override bool DoesStoreExist(string path, string fileName)
        {
            _logger.LogDebug($"DoesStoreExist: {path} {fileName}");

            string NOT_EXISTS = "no such file or directory";
            string result = RunCommand($"ls {path}{fileName}", null, ApplicationSettings.UseSudo, null);

            return !result.ToLower().Contains(NOT_EXISTS);
        }

        private string ReplaceSpacesWithLF(string privateKey)
        {
            return privateKey.Replace(" RSA PRIVATE ", "^^^").Replace(" ", System.Environment.NewLine).Replace("^^^", " RSA PRIVATE ");
        }

        private string FormatFTPPath(string path)
        {
            return path.Substring(0, 1) == @"/" ? path : @"/" + path.Replace("\\", "/");
        }
    }
}
