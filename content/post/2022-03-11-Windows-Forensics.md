---
categories: windows, forensic, malware, incident response
tags:
    - Malware Analysis
    - Incident Reponse
    - Forensics Analysis
    - Windows Forensics
date: "2022-03-11T15:48:37+01:00"
title: Windows Dead Box (Disk Image) Forensics
toc: true
---

## TL;DR:

**In case you are responding to an active incident:**

>There is simply *A LOT* to analyze in terms of forensic artifacts on
Windows systems. The process can take a long time, and slow down the IR
process. Below are some of the artifacts that tends to yield quick results.
>
>**Make sure to switch to offline disk analysis on these tools and point them to the right disk!**
>-   [WinLogOnView](#winlogonview): Which 
    account was logged into? From what IP? For how long? When?
>-   [Autoruns](#autoruns): List out all the
    persistence mechanisms in place
>     -   Do not forget to target the disk you are analyzing with `Analyze Offline System`
>-   [Shimcache (AppCompatCache)](#shimcache-appcompatcache): List of
    executed programs with date
>-   [AMcache](#amcache): Another list of
    programs executed on the system
>-   Files created in the past 7 days:
>
>     -   ```Get-ChildItem -Force -Path D:\ -Recurse -ea silentlycontinue| ? {$_.CreationTime -gt (Get-Date).AddDays(-7)}```

------------------------------------------------------------------------

**What to expect, if you have no experience with Windows forensics:**

>On Unix-like systems, [everything is a file](https://en.wikipedia.org/wiki/Everything_is_a_file). This means that even live processes will have a file corresponding to their relevant operations. For instance an `environ` file under the `/proc` pseudo-filesystem having the environment variables specific to that process. This provides an easy access to a lot of valuable information from a forensics perspective.
>
>Unfortunately for us, Windows does not have the same mindset. Even when
certain information sources have a file storing a copy of the same thing, they are usually in a binary format and the information is only accessible via special tools that are able to parse them.
>
>This makes forensics analysis of an offline disk rather more challenging for us for several reasons. One is the availability of the tools. Second is the not guaranteed backwards-compatibility of the tools and the artifacts' existence itself. And third, is the lower probability to `grep` through an entire filesystem for a known IOC and get a hit, due to the binary formats.
>
>Therefore it was necessary to compile this page with the locations of
relevant artifacts and the tools to parse them. I’ve manually tested
each of the artifacts and the related tools mentioned in this page on Win10 systems.

## Before You Begin

-   **This guide assumes your forensic host runs Windows OS**
-   **Are the disk(s) mounted with correct options?**

    -   **Disk must be mounted in** `Read-Only`

    -   **This can be ensured the following way:**

        -   Switch off `automount` by running `mountvol.exe /N`

        -   Connect disk to Windows (do not mount the disk)

        -   Run `diskpart`

        -   Enter `list volume`

        -   Enter `select volume X` (where X is the correct volume
            number from the previous command)

        -   Enter `att vol set readonly`

        -   Enter `detail vol` and ensure the read-only bit is set

        -   Now you can mount the volume and it will be read-only

        -   Enter `assign letter d` to mount the volume to drive `d`

-   **Is the forensic host using UTC? (it should be, but double-check)**
    -   **On Forensic Host:**
        -   Open up the command line

            -   Display current timezone with: `tzutil /g`

            -   Set the current timezone to UTC: `tzutil /s "UTC"`

        -   It can also be set from the GUI by executing `timedate.cpl`

-   **Make sure your PowerShell session is opened with Administrator
    privileges**

-   **How was the machine used (as far as you know)?**

    -   Is there a Web server, DB, or some other application being
        served? Those applications probably have their own separate logging somewhere. Make sure to take advantage of those.

------------------------------------------------------------------------

## The essentials
-   **Load the Registry**

    -   Windows registry holds a wealth of valuable information

    -   The first order of business before any analysis should be to
        make the registry of the victim host available for analysis

    -   You can use the
        <a href="#Registry-Explorer" rel="nofollow">Registry Explorer</a>
        tool to load offline registry hives from the disk.

    -   Load the following files with Registry Explorer:

        -   `D:\Windows\System32\config\SAM`: `HKEY_LOCAL_MACHINE`

        -   `D:\Windows\System32\config\SECURITY`: `HKEY_LOCAL_MACHINE`

        -   `D:\Windows\System32\config\SYSTEM`: `HKEY_LOCAL_MACHINE`

        -   `D:\Windows\System32\Config\SOFTWARE`: `HKEY_LOCAL_MACHINE`

        -   `D:\Windows\System32\Config\DEFAULT`: `HKEY_LOCAL_MACHINE`

        -   `D:\Users\<USERNAME>\NTUSER.DAT`: `HKEY_CURRENT_USER`

        -   If anything is missing, you might find the backups at:
            `D:\Windows\System32\config\RegBack\`

-   **Registry Explorer Tip:**

    -   It has a `Bookmarks` section that contains shortcuts to valuable
        registry hives. But it is triggered separately for each of the
        registry files that is loaded.

    -   To utilize it; first select the hive that you want to explore,
        then check the relevant bookmarks:

![image-20220228-121924.png](/assets/img/windows-forensics/1575501416.png)

------------------------------------------------------------------------

**Basic Information on Windows Registry**

Quoting from my copy of the [Windows Internals](https://docs.microsoft.com/en-us/sysinternals/resources/windows-internals) with a dusty cover:
>Although most people think of the registry as static data stored on the hard disk, as you'll see in this section, the registry is also a window into various in-memory structures maintained by the Windows executive and kernel.

Windows registry follows pretty much the same structure as filesystem
hierarchies. There are 5 root folders:

-   [**HKEY_CLASSES_ROOT (HKCR)**](https://docs.microsoft.com/en-us/windows/win32/sysinfo/hkey-classes-root-key)

    -   Stores data to associate file extensions with programs, and COM class registration information such as ProgIDs, CLSIDs.

-   **HKEY_CURRENT_USER (HKCU)**

    -   A subkey of `HKEY_USERS`

    -   It contains configuration information for Windows and software
        specific to the currently logged in user. Things such as Control Panel settings can be found here.

-   [**HKEY_LOCAL_MACHINE (HKLM)**](https://en.wikipedia.org/wiki/Windows_Registry#HKEY_LOCAL_MACHINE_(HKLM))

    -   Contains configuration information particular to the computer
        (for any user).

    -   HKLM is actually maintained in memory by the kernel in order to
        map all other subkeys. Applications cannot create any additional
        subkeys.

    -   This hive contains four keys;

        -   `SAM`: contains local user account and local group
            membership information, including their passwords, last
            login dates etc.

        -   `SECURITY`: stores systemwide security policies, and while that sounds important, you'll most likely won't be able to get anything useful out of here.

        -   `SYSTEM`: Stores systemwide configuration necessary to boot the system, like mounted drives, driver database, keyboard layout etc.

        -   `SOFTWARE`: Software specific configuration keys are stored
            here.

    -   These are loaded at boot time from their respective files
        located under the `D:\Windows\System32\config\` folder.

-   HKEY_USERS (HKU)

    -   Contains all the actively loaded user profiles on the computer.

-   HKEY_CURRENT_CONFIG (HKCC)

    -   Contains information about the hardware profile that is used by
        the local computer at system startup. Hardware profiles are no longer supported, so this is mostly legacy stuff.

For more information: [MSDN-windows-registry-advanced-users](https://docs.microsoft.com/en-us/troubleshoot/windows-server/performance/windows-registry-advanced-users)

------------------------------------------------------------------------

-   **Hostname and Domain**

    -   Select `System` registry hive from Registry Explorer.

    -   Select `ComputerName` from the bookmarks.

        -   Or go to the following key manually:
            `System\ControlSet001\Control\ComputerName\ComputerName`

    -   Select `SECURITY` registry hive from Registry Explorer.

    -   Select `Domain Name` from the bookmarks.

        -   Manually go to
            `D:\Windows\System32\config\SECURITY:Policy\PolDnDDN`

    -   Alternative:

        -   Check `SYSTEM\ControlSet001\Services\Tcpip\Parameters`

            -   Contains `Domains`, `DHCP` server information,
                `Hostname` etc.

-   **Timezone**

    -   Select `SYSTEM` registry hive from Registry Explorer.

    -   Select `TimeZoneInformation` from the bookmarks

        -   Manually: `SYSTEM\ControlSet001\Control\TimeZoneInformation`

-   **Usernames and SIDs**

    -   Select `SAM` registry hive from Registry Explorer.

    -   Select `Users` from the bookmarks.

    -   Check `Names` key, or `V` values name

        -   Manually you can check `SAM\Domains\Account\Users`

    -   Mapping SIDs to Usernames:

        -   Windows stores Security identifiers (SIDs) under the
            following registry key:
            `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`

        -   The Hive key corresponds to the SID. `ProfileImagePath`
            value name contains the username.

-   **Last Login Date, Account Information, Login Count**

    -   If you are only interested in last login date for each user,
        download [RegRipper from this link](https://github.com/keydet89/RegRipper3.0)

    -   Unzip and execute `rr.exe` (GUI version)

    -   For input, enter `D:\Windows\System32\config\SAM`, and specify
        any location for output

    -   Let it rip, and the output file will contain relevant login
        information for each user

    -   Example output:
		![image-20220228-121924.png](/assets/img/windows-forensics/1575501413.png)

-   **Last Login Date, Login Method, Session Length, and IP Address for
    Remote Connections**

    -   First, learn the location of `Event Logs`

        -   By default it resides at:
            `D:\Windows\system32\winevt\Logs\Application.evtx`

        -   If not, check the following registry key

            -   `SYSTEM:ControlSet001\Services\EventLog\Application\File`

            -   Registry Explorer already has a bookmark of this
                location

            -   Select `SYSTEM` hive, and from the `Bookmarks` menu
                select `EventLog`

    -   Download [WinLogOnView from the link](https://www.nirsoft.net/utils/windows_log_on_times_view.html)

        -   Click on `Options` → `Advanced Options`

        -   Change `Data Source` to `External Disk`

        -   Enter the `evtx` folder that you’ve determined in the
            previous step

        -   You will get an output like the following:
        ![image-20220228-121924.png](/assets/img/windows-forensics/1575501410.png)

## Persistence

-   There are dozens of different ways persistence can be achieved on
    Windows systems

-   Checking them manually is a cumbersome process

-   Luckily, `Autoruns` from SysInternals handles this very well,
    including for offline disks

-   **Download** [Autoruns from this link](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)

    -   If you are using the `GUI`:

        -   Click on `File` and select `Analyze Offline System`

        -   Enter `D:\Windows` as the `System Root` path

        -   It should automatically detect the `Default` profile and
            start to list out persistence mechanisms

            -   You can specify the user profile you want to work on too

        -   If you want, you can try to speed up your analysis process:

            -   Click on `Options` and select `Scan Options`

            -   Check the `Check VirusTotal.com`

            -   **DO NOT** check the `Submit Unknown Images`

                -   If you are dealing with an APT, this would alert them
                    that their sample has been discovered

            -   Now you can filter out all the clean, known Microsoft
                images

    -   If you are using the `CLI`:

        -   `autorunsc.exe -a * -c -h -s '*' -z D:\Windows D:\Users\Default -nobanner`

------------------------------------------------------------------------

-   **Autoruns already checks the locations below.**

    -   But if for some reason manual inspection is necessary, below are the most common places.

-   **Scheduled Tasks**

    -   Each `Scheduled Task` can be found as a separate file under:

        -   `D:\Windows\System32\Tasks` or `D:\Windows\SysWow64\Tasks`

-   **StartupInfo**

    -   Located under: `D:\Windows\System32\WDI\LogFiles\StartupInfo\`,
        in the following format: `<USER_SID>/StartupInfo<NUMBER>.xml`

    -   There could be up to 5 per user account. They contain a list of
        processes that were executed within the first 90 seconds from
        the time the user logged in.

    -   The info includes start time, the full command line and the
        parent process info, among other things.

-	**ExplorerStartupLog**

	-	Created when the system boots up, and located at:

		-   `D:\Users\Administrator\AppData\Local\Microsoft\Windows\Explorer\ExplorerStartupLog.etl`

    -   Can be opened with `Event Viewer`

-   **Run Keys**

    -   Probably the most commonly utilised persistence mechanism

    -   Any program under `Run` key will be executed at each start-up

    -   Whereas `RunOnce` executes it once, and deletes the key

    -   These keys can be found at:

        -   `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run`

        -   `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce`

        -   `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`

        -   `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce`

    -   `Registry Explorer` can used to access them easily

        -   Just select `Software`, and from the bookmarks go to `Run`
            or `RunOnce`

-   **Start Menu**

    -   Windows uses this folder to store shortcuts to programs to be
        executed on startup

    -   Files are located under:

        -   For `All Users`:

            -   `D:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`

        -   For `Current User`:

            -   `D:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`

## Web Server

-   **XAMPP Logs:**

    -   `D:\xampp\apache\logs`

-   **IIS:**

    -   `D:\inetpub\logs\LogFiles\W3SVC1`

        -   Note: replace 1 with the number for your IIS website ID

    -   `D:\Windows\System32\LogFiles\W3SVC1`

    -   `D:\Windows\System32\LogFiles\HTTPERR`

    -   In case the logs are not found in the folders above, you can
        check the following config:

        -   `D:\Windows\system32\inetsrv\config\ApplicationHost.config`

    -   If there is suspicion of a backdoor/webshell artifact, you can
        do searches such as:

        -   `grep.exe -Er "(ShellExecute|FromBase64String|StartInfo\.FileName|eval)" D:\inetpub\`

        -   `Get-ChildItem -Force -Path D:\inetpub\ -recurse -ea silentlycontinue |  Select-String -Pattern "FromBase64String"`

-   In case there is suspicion of a backdoor in the form of IIS
    modules:

    -   A native IIS module is a dynamic-link library (DLL) written
        using the IIS C++ API.

        -   Native modules are located in the
            `D:\Windows\system32\inetsrv\` folder on the server and can
            be configured for some, or for all, applications hosted by
            the server.

        -   Check
            `%windir%\system32\inetsrv\config\ApplicationHost.config`for the existence of these.

        -   Reference Paper: [Blackhat-us-21-Anatomy-Of-Native-Iis-Malware-wp.pdf](https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-Anatomy-Of-Native-Iis-Malware-wp.pdf)
-   **Exchange Web Server:**

    -   By default located under:
        - `$exinstall\Logging\Ews`

    -   At least 14 days of Exchange Control Panel (ECP) logs, located
        at `Program Files\Microsoft\Exchange Server\v15\Logging\ECP\Server`

## General Logs and Windows Event Logs

-   **Windows Event Logs**

    -   By default, Windows Event Logs are located under this folder:

        -   `D:\Windows\System32\winevt\Logs`

        -   If not, the location can be confirmed from:

            -   `SYSTEM:ControlSet001\Services\EventLog\Application\File`

        -   <a href="#Registry-Explorer" rel="nofollow">Registry Explorer</a>
            already has a bookmark of this location

        -   Select `SYSTEM` hive, and from the `Bookmarks` menu select
            `EventLog`

    -   The log files can then be loaded in with `Event Viewer` tool of
        Windows itself

        -   Run `Event Viewer`

        -   From the `Action` menu on top right, select `Open Saved Log`

        -   Load the desired log file from the folder you’ve located

        -   Alternatively, you can just double click on the log files
            and they will be loaded automatically

        -   `Windows PowerShell`, `Microsoft-Windows-PowerShell%4Operational`, `System`, `Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational` log files might be particularly useful

-   **RDP Logs**

    -   Windows Event Logs also contain RDP related logs

------------------------------------------------------------------------

-   Successful RDP Logon:

    ```YAML
    Event id: 1149
    Description:  User authentication succeeded.
    Path: %SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx
    Event id: 4624
    Description: An account was successfully logged on.
    Path: %SystemRoot%\System32\Winevt\Logs\Security.evtx
    Event id: 21
    Description: Remote Desktop Services: Session login succeeded.
    Path: %SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
    Event id: 22
    Description: Remote Desktop Services: Shell start notification received.
    Path: %SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
    ```

-   Unsuccessful RDP Logon:

    ``` YAML
    Event id: 1149
    Description:  User authentication succeeded (Network connection, which occurs prior to the user authentication).
    Path: %SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx
    Event id: 4625
    Description: An account failed to log on.
    Path: %SystemRoot%\System32\Winevt\Logs\Security.evtx
    ```

-   RDP Session Disconnect (windows close by the user):

    ``` YAML
    Event id: 24
    Description:  Remote Desktop Services: Session has been disconnected.
    Path: %SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
    Event id: 40
    Description: Session XXX has been disconnected, reason code YYY.
    Path: %SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
    Event id: 4779
    Description: A session was disconnected from a windows station.
    Path: %SystemRoot%\System32\Winevt\Logs\Security.evtx
    Event id: 4634
    Description: An account was logged off.
    Path: %SystemRoot%\System32\Winevt\Logs\Security.evtx
    ```

-   RDP Session Disconnect (Start -\> Disconnect):

    ``` YAML
    Event id: 24
    Description:  Remote Desktop Services: Session has been disconnected.
    Path: %SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
    Event id: 39
    Description: Session XXX has been disconnected, by session YYY.
    Path: %SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
    Event id: 40
    Description: Session XXX has been disconnected, reason code YYY.
    Path: %SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
    Event id: 4779
    Description: A session was disconnected from a window station.
    Path: %SystemRoot%\System32\Winevt\Logs\Security.evtx
    Event id: 4634
    Description: An account was logged off.
    Path: %SystemRoot%\System32\Winevt\Logs\Security.evtx
    ```

-   RDP Session Reconnect:

    ``` YAML
    Event id: 1149
    Description:  User authentication succeeded.
    Path: %SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx
    Event id: 4624
    Description: An account was successfully logged on.
    Path: %SystemRoot%\System32\Winevt\Logs\Security.evtx
    Event id: 25
    Description: Remote Desktop Services: Session reconnection succeeded.
    Path: %SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
    Event id: 40
    Description: Session XXX has been disconnected, reason code YYY.
    Path: %SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
    Event id: 4778
    Description: A session was reconnected from a window station.
    Path: %SystemRoot%\System32\Winevt\Logs\Security.evtx
    ```

-   RDP Session Logoff :

    ``` YAML
    Event id: 23
    Description:  Remote Desktop Services: Session logoff disconnected.
    Path: %SystemRoot%\System32\Winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx
    Event id: 4634
    Description: An account was logged off.
    Path: %SystemRoot%\System32\Winevt\Logs\Security.evtx
    Event id: 4647
    Description: User-initiated logoff.
    Path: %SystemRoot%\System32\Winevt\Logs\Security.evtx
    Event id: 9009
    Description: The Desktop Window Manager has exited with code XXX.
    Path: %SystemRoot%\System32\Winevt\Logs\System.evtx
    ```

-   Reference: [RDP Forensics - Logging, Detection and Forensics](https://www.security-hive.com/post/rdp-forensics-logging-detection-and-forensics)

------------------------------------------------------------------------

-   **RDP Cache**

    -   `mstsc.exe` is the built-in client that allows connecting to
        remote computers via RDP

    -   It stores an RDP cache with the aim to speed up the connection

    -   This cache contains screenshots of the parts of the screen that
        does not change much

    -   Through this cache, you may be able to find out if the victim
        host was used to connect to other hosts via RDP

        -   `D:\Users\<username>\AppData\Local\Microsoft\Terminal Server Client\Cache`

        -   [bmc-tools](https://github.com/ANSSI-FR/bmc-tools) can be used to extract images from the bin file

-   **User Access Logging**

    -   [It was discovered and documented by DFIR team of KPMG](https://advisory.kpmg.us/blog/2021/digital-forensics-incident-response.html):

        -   `The UAL can be found on Windows Servers (2012 and up) and is a local data aggregation feature, recording client usage by role and product on each system providing the resource.`

        -   `According to Microsoft's documentation these logs will:`

            -   Keep a tally of user requests for local servers,
                physical or virtual

            -   Keep a tally of user requests for local software
                products on these servers

            -   Pull statistics from Hyper-V, regarding high and low
                periods of demand for resources

            -   Pull UAL data from remote servers

    -   Logs are located under `D:\Windows\System32\LogFiles\Sum`

    -   Instructions on how to examine the UAL data: [Windows User Access Logs (UAL)](https://svch0st.medium.com/windows-user-access-logs-ual-9580f1100635)

    -   [KStrike](https://github.com/brimorlabs/KStrike) can be used to parse the data as well

## Deposited Files & Filesystem Artifacts

-   **LOLBIN Downloaded Files**

    -   `LOLBINs` such as `certutil` are frequently leveraged by
        attackers to download next stages

        -   A list of its capabilities for attackers: [LOLBAS-Certutil](https://lolbas-project.github.io/lolbas/Binaries/Certutil/)

    -   Files downloaded with `certutil` have a copy of them stored in
        some of the following locations:

        -   `MetaData` folder holds the URL of the each file downloaded,
            while `Content` folder holds the files themselves.

        -   So if you are unsure where a file came from, just open the
            corresponding file in MetaData folder with `strings.exe`, or
            `notepad.exe`.

    -   <div class="code panel pdl" style="border-width: 1px;">

        <div class="codeContent panelContent pdl">

        ``` yaml
        D:\Windows\SysWOW64\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content\
        D:\Windows\SysWOW64\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData\
        D:\Windows\System32\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content\
        D:\Windows\System32\config\systemprofile\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData\
        D:\Users\%USERNAME%\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content\
        D:\Users\%USERNAME%\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData\
        ```

        </div>

        </div>

    -   Further reading: [thinkdfir-certutil-download-artefacts](https://thinkdfir.com/2020/07/30/certutil-download-artefacts/amp/)

-   **Deleted Files**

    -   `D:\$Recycle.Bin` folder contains folders with each users’ `SID`

        -   Under the users’ SID there are files which begin with `$I`
            and `$R`

        -   When a file is deleted two files are created:

            -   `$R` file contains the actual file that was deleted

            -   `$I` file contains the metadata of the deleted file

-   **Malicious Hosts Entries**

    -   `Hosts` file can be used to hijack traffic to malicious websites

    -   It takes precedence over DNS queries

    -   It is located at:

        -   `D:\Windows\System32\drivers\etc\hosts`

        -   `D:\Windows\System32\drivers\etc\lmhosts.sam`

### Recently Accessed, Created, and Modified Files

-   **Files modified within the past 7 days**

    -   `Get-ChildItem -Force -Path D:\ -Recurse -ea silentlycontinue| ? {$_.LastWriteTime -gt (Get-Date).AddDays(-7)}`

-   **Files accessed within the past 7 days**

    -   `Get-ChildItem -Force -Path D:\ -Recurse -ea silentlycontinue| ? {$_.LastAccessTime -gt (Get-Date).AddDays(-7)}`

-   **Files created within the past 7 days**

    -   `Get-ChildItem -Force -Path D:\ -Recurse -ea silentlycontinue| ? {$_.CreationTime -gt (Get-Date).AddDays(-7)}`

## Evidence of Program Execution

### UserAssist

-   A registry key under `NTUSER.DAT` hive

-   It provides a list of **GUI based programs** launched from the
    desktop

-   To examine the data:

    -   First navigate to

        -   `NTUSER.DAT: Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist{<GUID>}\Count`

        -   `Registry Explorer` has a bookmark of this location already

            -   Just click on `NTUSER.DAT`, and select `UserAssist` from
                the bookmarks menu

    -   Pick the items with a `Count` greater than `0`

    -   The contents are encoded with `ROT13`

        -   For instance, the value below is decoded to:

            -   `{0139Q44R-6NSR-49S2-8690-3QNSPNR6SSO8}\Npprffbevrf\Favccvat Gbby.yax`

            -   `{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}\Accessories\Snipping Tool.lnk`

    -   Alternatively, you can use `RegRipper` to do these steps
        automatically

        -   Download <a href="#" rel="nofollow">RegRipper</a>

        -   Unzip and execute `rr.exe` (GUI version)

        -   For input, enter `D:\Users\<username>\NTUSER.DAT`, and
            specify any location for output

        -   Let it rip, and the output file will contain relevant
            execution history

        -   Search for `UserAssist` in the output file

### Prefetch

-   Prefetching is a system that helps systems boot up and run faster by
    caching needed files ahead of time

-   Prefetch can be very valuable, as it contains the following data:

    -   Name of the executable ran

    -   Unicode list of DLLs used by that executable

    -   Count of how many times the executable has been run

    -   Timestamp indicating the last time the program was executed

-   Prefetch logs are located at `D:\Windows\Prefetch`

-   `WinPrefetchView` can be used to view them, and it supports loading
    them from an external disk for forensic analysis: [nirsoft-win_prefetch_view.html](https://www.nirsoft.net/utils/win_prefetch_view.html)

-   Alternatively, `PECmd` from the [Zimmerman-Tools](#zimmerman-tools) can be
    used as well

    -   Simply run the following in the directory that the tools are
        installed in:

        -   `.\PECmd.exe -d D:\Windows\Prefetch --html "C:\Users\Administrator\Desktop\output"`

### SuperPrefetch

-   Pretty much the same as `Prefetch`, but it is not a substitution for
    it

-   Generates the database files at:

    -   `D:\Windows\Prefetch\Ag*.db`

-   You can use [CrowdResponse](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) to parse the data

### StartupInfo

- Mentioned earlier for detecting persistence, it gives a glimpse of executed programs

-   Located under: `D:\Windows\System32\WDI\LogFiles\StartupInfo\`,
        in the following format: `<USER_SID>/StartupInfo<NUMBER>.xml`

-   There could be up to 5 per user account. They contain a list of
        processes that were executed within the first 90 seconds from
        the time the user logged in.

-   The info includes start time, the full command line and the
        parent process info, among other things.

### Crash Dumps

-   **Minidumps**

    -   When your computer crashes, Windows generates a `Minidump` that
        can be examined to determine the root cause

    -   These minidump files are placed under:

        -   `D:\Windows\Minidump`

    -   To analyze, refer to the official guide: [MSDN-read-small-memory-dump-file](https://docs.microsoft.com/en-us/troubleshoot/windows-client/performance/read-small-memory-dump-file)

-   **Crash Dumps**

    -   Crash dumps are generated automatically if certain Registry keys
        are set

    -   Analyzing these is not such a straightforward, trivial task, and therefore skipped
        in this guide

    -   These are located under

        -   `D:\Users\[username]\AppData\Local\CrashDumps`

        -   `D:\Users\[username]\AppData\Local\Microsoft\Windows\WER\`

### WMI CCM_Recently_Used_Apps

-   [Windows Management Instrumentation](http://technet.microsoft.com/en-us/library/cc753534.aspx)(WMI) is a built-in tool

-   Allows admins to manage different Windows environments, including
    remote systems

-   It is a frequently used `LOLBIN`: [LOLBAS-Wmic](https://lolbas-project.github.io/lolbas/Binaries/Wmic/)

-   The WMI Repository is a database that stores meta-information and definitions for WMI classes

    -   The logging occurs on the endpoints regardless of the settings
        that are configured on the SCCM server

    -   Can record the path, name, size, associated user name, last used
        time, launch count, and PE metadata of executed files

    -   Located at `D:\windows\system32\wbem\repository\`

    -   Can be parsed with: [github-CCM_RUA_Finder.py](https://github.com/davidpany/WMI_Forensics/blob/master/CCM_RUA_Finder.py)

        -   Simply run
            `CCM_RUA_Finder.py -i D:\windows\system32\wbem\repository\OBJECTS.DATA -o path\to\output.xls`

            -   If the forensic host does not have Python installed, you
                can exfiltrate the files to your own workstation

            -   The `Microsoft Remote Desktop` tool used for RDP
                connections on MacOS devices supports copy-paste

-   Further reading: [netsecninja-wmi-forensics](https://netsecninja.github.io/dfir-notes/wmi-forensics/)

-   Comprehensive guide: [mandiant-windows-management-instrumentation-wmi-offense-defense-and-forensics](https://www.mandiant.com/resources/windows-management-instrumentation-wmi-offense-defense-and-forensics)

### Shimcache (AppCompatCache)

-   `Windows Application Compatibility Database` is used by Windows to
    identify possible application compatibility challenges with
    executables.

-   It tracks the executables’ file name, file size, last modified time.

-   Last 1024 programs executed can be found here:

    -   `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`

    -   `Registry Explorer` has a bookmark of this location

        -   Select `SYSTEM`, and from the bookmarks menu, go to
            `AppCompatCache`

-   Alternatively, [github-mandiant-ShimCacheParser](https://github.com/mandiant/ShimCacheParser) can
    be used to parse the data

    -   Just export the whole `SYSTEM` registry hive, or the
        `AppCompatCache` as a standalone `.reg` file

        -   `Registry Explorer` can be used to export the key

    -   Use the `-i`, or `-r` option respectively

    -   Output will be as follows:

    -   ![image-forensics-shimcache.png](/assets/img/windows-forensics/1575501404.png)

### AMcache

-   `ProgramDataUpdater` (a task associated with the Application
    Experience Service) uses the registry file `Amcache.hve` to store
    data during process creation

-   This registry stores the first execution of a program on the system,
    including portable programs executed from an external storage.

-   It is located at:

    -   `D:\Windows\AppCompat\Programs\Amcache.hve`

-   To analyze, use [RegRipper](#regripper)

    -   Load the `Amcache.hve` file

    -   Select an output destination, and `Rip`

    -   You will get an output like the following:

    -   ![image-forensics-amcache.png](/assets/img/windows-forensics/1575501401.png)

### Background Activity Moderator

-   The Background Activity Moderator (BAM) is a Windows service that
    Controls activity of background applications. This service exists in
    Windows 10 only.

-   For each user separately, it provides:

    -   Full path of the executable file

    -   Last execution date/time in UTC

-   It is located under the following keys:

    -   `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\UserSettings\*\*`

    -   `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\*\*`

    -   `Registry Explorer` has a bookmark for it

        -   Select `SYSTEM` hive

        -   From the `Bookmarks` menu, select
            `BAM (Background Activity Monitor)`

## Tools

### Registry Explorer

One of the Zimmerman tools, but a particularly useful one that it
deserves its own space.

-   It is able to explore both Live system registry hives, and offline
    ones

-   Has a `Bookmarks` tab with shortcuts to keys with valuable forensic
    artifacts

-   Can be downloaded from: [ericzimmerman.github.io](https://ericzimmerman.github.io/#!index.md)

### Zimmerman Tools

Eric Zimmerman has written plenty of tools and scripts to perform offline
disk analysis.

-   To install them all, follow the instructions at: [ericzimmerman.github.io](https://ericzimmerman.github.io/#!index.md)

    -   Use [backblazeb2-Get-ZimmermanTools.zip](https://f001.backblazeb2.com/file/EricZimmermanTools/Get-ZimmermanTools.zip) to download all programs at once and to keep your toolset up-to-date

        -   Use **-Dest** to control where the tools ends up, else
            things end up in same directory as the script (recommended!)

### Power Forensics

-   It is an all-inclusive forensics framework written in PowerShell

-   Supports `NTFS` and `FAT` filesystems

-   Although not utilised in this page for any of the artifacts, it is particularly useful for
    filesystem forensics

-   Documentation with available tools: [powerforensics.readthedocs.io](https://powerforensics.readthedocs.io/en/latest/)

### RegRipper

-   It is a powerful and easy to use tool to parse out various
    information from registry files.

-   It comes with a bunch of plugins to parse data from hives such as
    `SAM`, `SOFTWARE`, `NTUSER` etc.

-   Both GUI and CLI versions are available.

-   Download from: [github.com/keydet89/RegRipper3.0](https://github.com/keydet89/RegRipper3.0)

### Autoruns

-   It is a Sysinternals tools, officially developed and
    supported by Microsoft

-   It is able to enumerate tons of different persistence mechanisms on Windows

-   It can be executed both via CLI and GUI

-   It is able to perform analysis on offline systems and disks as well

-   Download and manual link: [MSDN-sysinternals-autoruns](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)

### WinLogOnView

-   A simple and concise tool by Nirsoft with one goal:

-   `Analyses the security event log of Windows operating system, and detects the date/time that users logged on and logged off. For every time that a user log on/log off to your system, the following information is displayed: Logon ID, User Name, Domain, Computer, Logon Time, Logoff Time, Duration, and network address.`

-   Download from: [nirsoft-windows_log_on_times_view.html](https://www.nirsoft.net/utils/windows_log_on_times_view.html)

### THOR

-   THOR lite can scan both a live system or an offline mounted disk for
    IOCs. THOR already comes equipped with its own list of IOCs to scan
    for. But you can add your own stuff too -if your license allows to it-.

-   If you have a `Forensic Lab License`:

    -   Thor Lite can be used on a disk
        `thor64-lite.exe --fsonly -p D:\`

-   If you are using the `LITE` -free- version: [thor-manual-forensic-lab-license](https://thor-manual.nextron-systems.com/en/latest/usage/special-scan-modes.html#forensic-lab-license)

    -   `thor64.exe -a Filescan --intense --norescontrol --nosoft --cross-platform --alldrives -p D:\`

-   In my experience, THOR gave quite some FPs. For instance, on a
    default installation it said some files masquerade as JPGs and that
    they are not actually JPGs:

        ``` java
        MESSAGE: Suspicious file found
        FILE: D:\Windows\servicing\LCU\Package_for_RollupFix~31bf3856ad364e35~amd64~~17763.2565.1.7\amd64_microsoft-windows-f..toragereportservice_31bf3856ad364e35_10.0.17763.1697_none_7825694087316827\f\warning.jpg
        REASON_1: YARA rule Cloaked_as_JPG / Detects a non-JPEG file cloaked as
        ```
