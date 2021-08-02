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
using System.Threading.Tasks;

using CSS.Common.Logging;

namespace JavaKeyStoreSSH.RemoteHandlers
{
    abstract class BaseRemoteHandler : LoggingClientBase, IRemoteHandler
    {
        internal const string KEYTOOL_ERROR = "password was incorrect";
        internal const string PASSWORD_MASK_VALUE = "[PASSWORD]";
        internal const int PASSWORD_LENGTH_MAX = 100;

        public string Server { get; set; }

        public abstract void Initialize();

        public abstract void Terminate();

        public abstract string RunCommand(string commandText, object[] arguments, bool withSudo, string[] passwordsToMaskInLog);

        public abstract void UploadCertificateFile(string path, string fileName, byte[] certBytes);

        public abstract void RemoveCertificateFile(string path, string fileName);

        public abstract bool DoesStoreExist(string path, string fileName);
    }
}
