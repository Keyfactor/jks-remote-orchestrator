v1.1.0
- Add local PAM capability for resolving the server password
- Fix race condition issue when concurrent jobs modify a single keystore by adding Mutex

v1.0.10
- Added optional Management Custom Job Field - entryPassword - Allows for a separate key password from the store password.  If not supplied, they key password will be set as the store password

v1.0.9
- Modified to perform all SSH functions for a job within one SSH connection
- Added additional validation for config.json file

v1.0.8
- Added new config.json option, FindKeytoolPathOnWindows.  If set to "Y", for Windows orchestrated servers, all logical drives will be searched for the first occurance of keytool.exe.  That path will then be used for all "keytool" commands.
- Ignore confirmation message when adding a certificate in a Windows java keystore.  Keytool was incorrectly sending this message to stderr causing an false error to be returned.
- Added option to Get-ChildItem command to ignore permissions errors on individual folders during recursive processing.  Process will now "silently continue".

v1.0.7
- Ignore warnings keytool flags as errors when working against keystores on windows servers.  
- Remove extraneous debug logging statements.

v1.0.6
- Fix inventory issue against windows orchestrated servers.  Carriage return was being included in alias names.  Also fix error logging bug.

v1.0.5
- Validate that Java is installed on Windows Orchestrated servers

v1.0.4
- Added "fullscan" functionality for Discovery, allowing recursive search for against Windows servers of all local drives on the orchestrated Windows server.
