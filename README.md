## Overview

The JavaKeystore AnyAgent allows a user to discover, inventory, and manage (both add and remove) Java Keystore certificate stores on both Windows and Linux servers.

The prerequisite for using the JavaKeystore AnyAgent to manage/orchestrate a Linux or Windows server is that Java be installed on each server being managed/orchestrated.


## Use Cases

The JavaKeystore Windows AnyAgent implements the following capabilities:
1. Create - Create a JavaKeystore.
2. Discovery - Discover all Javakeystores in a set of paths based on optional list of file extensions and partial name matching.
3. Inventory - Return all certificates for a define certificate store.
4. Management (Add) - Add a certificate to a defined certificate store.
5. Management (Remove) - Remove a certificate from a defined certificate store.

The JavaKeystore Windows AnyAgent supports the following types of JavaKeysore:
1. Trust stores (multiple public certificates with no private keys)
2. Stores with one or more aliases
3. Stores with certificate chains included in the alias (inventory only)


## Versioning

The version number of a the JavaKeystore Windows AnyAgent can be verified by right clicking on the JavaKeyStoreSSH.dll file in the Plugins installation folder, selecting Properties, and then clicking on the Details tab.


## Keyfactor Version Supported

The JavaKeystore Windows AnyAgent has been tested against Keyfactor version 8.5.2 but should work against earlier or later versions.


## Security Considerations

**For Linux orchestrated servers:**
1. The JavaKeystore AnyAgent makes use of the Keytool program and other common Linux commands such as "cp" and "find".  If the credentials you will be connecting with will need elevated access to run these commands, you must set the id up as a sudoer with no password necessary and set the config.json "UseSudo" value to "Y" (See Section 4 regarding the config.json file).
2. The JavaKeystore AnyAgent makes use of SFTP to transfer files to and from the orchestrated server.  SFTP will not mske use of sudo, so all folders containing certificate stores will need to allow SFTP file transfer.  If this is not possible, set the values in the config.json apprpriately to use an alternative upload/download folder that does have SFTP file transfer (See Section 4 regarding the config.json file).
3. To manage Java keystores, Java itself must be installed on the orchestrated server.  Wtih Java comes the Keytool program.  The path where Java and Keytool reside must be in the $PATH system environment variable on the orchestrated server.  If this is not possible, please review Section 4 regarding the config.json file to find information on setting up a client-written bash script to find the path where Keytool resides.

**For Windows orchestrated servers:**
1. Make sure that WinRM is set up on the orchestrated server and that the WinRM port is part of the certificate store path when setting up your certificate stores (See Section 3a below). 
2. By default, the location of the Keytool program needs to be in the Windows System Environment PATH variable of the orchestrated server.  If this is not possible, you can set the config.json item "FindKeytoolPathOnWindows" to "Y" to find it.  When this value is set to "Y", the JavaKeystore AnyAgent will search all available drives for the first occurance of "Keytool.exe" and use that to execute all Keytool commands.  See Section 4 regarding the config.json file below.


## JavaKeystore AnyAgent Configuration

**1. Create the New Certificate Store Type for the New JavaKeystore AnyAgent**

In Keyfactor Command create a new Certificate Store Type similar to the one below:

![](Images/Image1.png)

- **Name** – Required. The display name of the new Certificate Store Type
- **Short Name** – Required. **MUST** be &quot;JKS-SSH&quot;
- **Needs Server, Blueprint Allowed, Requires Store Password, Supports Entry Password** – All checked/unchecked as shown
- **Supports Custom Alias** – Required. Each certificate MUST have an alias associated with it for the store.
- **Use PowerShell** – Unchecked
- **Store PathType** – Freeform (user will enter the the location of the store)
- **Private Keys** – Optional (a certificate in a Java Keystore may or may not contain a private key)
- **PFX Password Style** – Default
- **Job Types** – Discovery, Inventory, Add, and Remove are the 3 job types implemented by this AnyAgent
- **Management Job Custom Fields** - Set to "entryPassword".  This will allow users when enrolling a new certificate with certificate store delivery or adding an existing certificate to a store to specify a separate password from the certificate store password to be used as the key password for that entry.  If this field is left blank when adding a certificate to a store, the store password will be used for the key password.  You can optionally omit setting this field up on the Certificate Store Type set up screen.  In this case the key password will ALWAYS be set to the store password.

**2. Register the JavaKeystore AnyAgent with Keyfactor**

Open the Keyfactor Windows Agent Configuration Wizard and perform the tasks as illustrated below:

![](Images/Image2.png)

- Click **\<Next\>**

![](Images/Image3.png)

- If you have configured the agent service previously, you should be able to skip to just click **\<Next\>.** Otherwise, enter the service account Username and Password you wish to run the Keyfactor Windows Agent Service under, click **\<Update Windows Service Account\>** and click **\<Next\>.**

![](Images/Image4.png)

- If you have configured the agent service previously, you should be able to skip to just re-enter the password to the service account the agent service will run under, click **\<Validate Keyfactor Connection\>** and then **\<Next\>.**

![](Images/Image5.png)

- Select the agent you are adding capabilities for (in this case, JavaKeystore, and also select the specific capabilities (Discovery, Inventory and Management in this example). Click **\<Next\>**.

![](Images/Image6.png)

- For agent configuration purposes, this screen can be skipped by clicking **\<Next\>**.

![](Images/Image7.png)

- For each AnyAgent implementation, check **Load assemblies containing extension modules from other location** , browse to the location of the compiled AnyAgent dll, and click **\<Validate Capabilities\>**. Once all AnyAgents have been validated, click **\<Apply Configuration\>**.

![](Images/Image8.png)

- If the Keyfactor Agent Configuration Wizard configured everything correctly, you should see the dialog above.

**3a. (Optional) Create a JavaKeystore Certificate Store within Keyfactor Command**

If you choose to manually create a JavaKeystore store In Keyfactor Command rather than running a Discovery job to automatically find the store, you can navigate to Certificate Locations =\> Certificate Stores within Keyfactor Command to add the store. Below are the values that should be entered.

![](Images/Image9.png)

- **Category** – Required. The JKS SSH	 type name must be selected.
- **Container** – Optional. Select a container if utilized.
- **Client Machine &amp; Credentials** – Required. The server name or IP Address and login credentials for the server where the Certificate Store is located.  The credentials for server login can be any of:
  
  - UserId/Password
  
  - UserId/SSH private key (entered in the password field)
  
  - PAM provider information to pass the UserId/Password or UserId/SSH private key credentials
  
  When setting up a Windows server, the format of the machine name must be – [http://_ServerName_:5985](http://ServerName:5985/), where &quot;5985&quot; is the WinRM port number. 5985 is the standard, but if your organization uses a different, use that.  The credentials used will be the Keyfactor Command service account.  Because of this, for Windows orchestrated servers, setting an additional set of credentials is not necessary.  **However, it is required that the *Change Credentials* link still be clicked on and the resulting dialog closed by clicking OK.**
  
- **Store Path** – Required. The FULL PATH and file name of the Java Keystore being managed. File paths on Linux servers will always begin with a &quot;/&quot;. Windows servers will always begin with the drive letter, colon, and backslash, such as &quot;c:\&quot;.
- **Orchestrator** – Select the orchestrator you wish to use to manage this store
- **Store Password** – Set the store password or set no password after clicking the supplied button
- **Inventory Schedule** – Set a schedule for running Inventory jobs or none, if you choose not to schedule Inventory at this time.

**3b. (Optional) Schedule a JavaKeystore Discovery Job**

Rather than manually creating JavaKeystore certificate stores, you can schedule a Discovery job to search an orchestrated server and find them.

First, in Keyfactor Command navigate to Certificate Locations =\> Certificate Stores. Select the Discover tab and then the Schedule button. Complete the dialog and click Done to schedule.

![](Images/Image10.png)

- **Category** – Required. The JavaKeystore type name must be selected.
- **Orchestrator** – Select the orchestrator you wish to use to manage this store
- Client Machine &amp; Credentials** – Required. The server name or IP Address and login credentials for the server where the Certificate Store is located.  The credentials for server login can be any of:

  - UserId/Password

  - UserId/SSH private key (entered in the password field)

  - PAM provider information to pass the UserId/Password or UserId/SSH private key credentials

  When setting up a Windows server, the format of the machine name must be – [http://_ServerName_:5985](http://ServerName:5985/), where &quot;5985&quot; is the WinRM port number. 5985 is the standard, but if your organization uses a different, use that.  The credentials used will be the Keyfactor Command service account.  Because of this, for Windows orchestrated servers, setting an additional set of credentials is not necessary.  **However, it is required that the *Change Credentials* link still be clicked on and the resulting dialog closed by clicking OK.**
- **When** – Required. The date and time when you would like this to execute.
- **Directories to search** – Required. A comma delimitted list of the FULL PATHs and file names where you would like to recursively search for Java Keystores. File paths on Linux servers will always begin with a &quot;/&quot;. Windows servers will always begin with the drive letter, colon, and backslash, such as &quot;c:\\&quot;.  Entering the string "fullscan" when Discovering against a Windows server will automatically do a recursive search on ALL local drives on the server.
- **Directories to ignore** – Optional. A comma delimitted list of the FULL PATHs that should be recursively ignored when searching for Java Keystores. Linux file paths will always begin with a &quot;/&quot;. Windows servers will always begin with the drive letter, colon, and backslash, such as &quot;c:\\&quot;.
- **Extensions** – Optional but suggested. A comma delimitted list of the file extensions (no leading &quot;.&quot; should be included) the job should search for. If not included, only valid Java Keystore files in the searched paths that have **no file extension** will be returned. If providing a list of extensions, using &quot;noext&quot; as one of the extensions will also return valid Java Keystores with no file extension. For example, providing an Extensions list of &quot;jks, noext&quot; would return all valid Java Keystore locations within the paths being searched with a file extension of &quot;jks&quot; and files with no extensions.
- **File name patterns to match** – Optional. A comma delimitted list of full or partial file names (NOT including extension) to match on.  Use "\*" as a wildcard for begins with or ends with.  Example: entering "ab\*, \*cd\*, \*ef, ghij" will return all stores with names that _**begin with**_ "ab" AND stores with names that _**contain**_ "cd" AND stores with names _**ending in**_ "ef" AND stores with the _**exact name**_ of "ghij".
- **Follow SymLinks** – NOT IMPLEMENTED. Leave unchecked.
- **Include PKCS12 Files** – NOT APPLICABLE. Leave unchecked.

Once the Discovery job has completed, a list of Java Keystore locations should show in the Certificate Stores Discovery tab in Keyfactor Command. Right click on a store and select Approve to bring up a dialog that will ask for the Keystore Password. Enter the store password, click Save, and the Certificate Store should now show up in the list of stores in the Certificate Stores tab.

**4. Update Settings in config.json**

The JavaKeystore AnyAgent uses the Java command line tool &quot;Keytool&quot; to discover, inventory, and manage Java Keystores. The AnyAgent assumes that the location for this command exists in the %Path% environment variable for each server being managed/orchestrated. On Linux servers, in situations where this is not the case, an optional, client-created, bash script can be configured to run at the beginning of each Discovery, Inventory, or Management job. Also there are times, a client may prefer to use their own logic to return matching files for a Discovery job. This custom script can be used for this as well.

As a configuration step, you must modify the config.json file, found in the plugins folder of your Keyfactor Agent JKS-SSH installation (usually C:\Program Files\Certified Security Solutions\Certificate Management System Agent\plugins\JKS-SSH). This file contains the following JSON:

{
    
&quot;UseSudo&quot;: &quot;N&quot;,

&quot;UsePrerunScript&quot;: &quot;N&quot;,

&quot;PreRunScript&quot;: &quot;ScriptName.sh&quot;

&quot;PreRunScriptDestinationPath&quot;: &quot;/path/to/script/&quot;

&quot;UseSeparateUploadFilePath&quot;: &quot;N&quot;,

&quot;SeparateUploadFilePath&quot;: &quot;/path/to/upload/folder/&quot;,

&quot;FindKeytoolPathOnWindows&quot;: &quot;N&quot;

}

Modify the six values as appropriate (all must be present regardless of Linux or Windows server orchestration):

**UseSudo** (Linux only) - to determine whether to prefix certain Linux command with "sudo". This can be very helpful in ensuring that the user id running commands ssh uses "least permissions necessary" to process each task. Setting this value to "Y" will prefix all Linux commands with "sudo" with the expectation that the command being executed on the orchestrated Linux server will look in the sudoers file to determine whether the logged in ID has elevated permissions for that specific command. For orchestrated Windows servers, this setting has no effect. Setting this value to "N" will result in "sudo" not being added to Linux commands.

**UsePrerunScript** (Linux only) – &quot;Y&quot; – The script identified in &quot;PreRunScript&quot; will be executed prior to the rest of the job. &quot;N&quot; – Do not run any pre-precessing script.

**PreRunScript** (Linux only) - The name of the script to be run on the orchestrated/managed server. This value will be ignored if UsePrerunScript is not set to &quot;Y&quot;. This script MUST be located in the JKS-SSH installation folder.

**PreRunScriptDestinationPath** (Linux only) – The folder on the destination/orchestrated Linux server where the script should be copied to and executed from. The script will be removed at the end of the job.

**UseSeparateUploadFilePath** (Linux only) – When adding a certificate to a Java Keystore, the Java Keystore SSH AnyAgent must upload the certificate being deployed to the server where the certificate store resides. Setting this value to &quot;Y&quot; looks to the next setting, SeparateUploadFilePath, to determine where this file should be uploaded. Set this value to &quot;N&quot; to use the same path where the Java Keystore being managed resides. The certificate file uploaded to either location will be removed at the end of the process.

**SeparateUploadFilePath** (Linux only) – Only used when UseSeparateUploadFilePath is set to &quot;Y&quot;. Set this to the path you wish to use as the location to upload and later remove certificates to be added to the Java Keystore being maintained.

**FindKeytoolPathOnWindows** (Windows only) – &quot;Y&quot; – The AnyAgent will search all available logical drives of the orchestrated server for the location of the "keytool.exe" program.  This path will be used for all subsequent "keytool" commands. &quot;N&quot; – The "keytool.exe" program is assumed to be in the system environment %PATH% variable.


Json format that MUST be returned by script identified in **PreRunScript** if **UsePrerunScript** is set to &quot;Y&quot;:

    {
        "KeyToolPath": "string",
        "DiscoveredFiles":
        [
            "string",
            "string",
            .
            .
            .
            "string"
        ]
    }

KeyToolPath is required but DiscoveredFiles is optional and only necessary if the client wishes to use their own logic to return certificate store locations.

KeyToolPath should contain the path where the Keytool command line program can be found on the orchestrated/managed server, and DiscoveredFiles, if exists, should contain an array of file paths and names of potential certificate stores based on the comma delimitted list of file extensions passed as input. If no extensions are passed, DiscoveredFiles does not need to be returned and a JSON format of:

    {
        "KeyToolPath": "string"
    }

is acceptable.
