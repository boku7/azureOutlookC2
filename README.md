## Azure Outlook C2
Azure Outlook Command &amp; Control that uses Microsoft Graph API for C2 communications &amp; data exfiltration. 

_Remotely Control a compromised Windows Device from your Outlook Mailbox._

#### Creators: [Bobby Cooke (@0xBoku)](https://twitter.com/0xBoku) &  [Paul Ungur (@C5pider)](https://twitter.com/C5pider) 

## Update (09/27/21)
+ Azure Outlook C2 now has a cross-platform Graphical User Interface (GUI)!
  + Big shoutout to [Paul Ungur (@C5pider)](https://twitter.com/C5pider) for teaching me how to create a C2 GUI with [QT](https://www.qt.io/)!

### Controlling a Computer via Outlook Mailbox with the C2 GUI
![](/assets/azureC2Gui.gif)

### Controlling a Computer via Outlook Mailbox
+ The update supports original Outlook Mailbox control.
![](/assets/azureOutlookC2Demo.gif)

_If you have any information about similar projects, CTI info about this TTP being used in the wild by APT/ransomware-groups, defense advice, recommendations for Red Teamers interested in Azure C2 threat emulation, or any other information that would be a good add to this blog/readme, please contact me or submit a Pull Request. Thank you!_

## About Azure Outlook C2
This project consists of an implant that beacons out to an Attacker-Controlled Azure Outlook mailbox, which acts as the Command & Control (C2); remotely controlling the compromised device. An Azure Refresh Token for the Attackers C2 mailbox is hard-coded into the implant during compilation. When executed on a Windows device, the implant accesses the Attackers Draft mailbox via the Microsoft Graph API. The implant reads command instructions from the Attackers Draft mailbox, executes the instructions locally on the compromised windows device, and returns the command output to the Attacker via creation of new Draft messages. The implant repeats this behavior of being remotely controlled from the Attackers mailbox until the implant host process is exited.

### Why I Built This
I recently started Red Teaming about half a year ago on the SpiderLabs Red Team at Trustwave. During an engagement I had the honor to work with the legendary [Stephan Borosh (rvrsh3ll|@424f424f)](https://twitter.com/424f424f). Steve & [Matt Kingstone](https://twitter.com/n00bRage) taught me all about Azure Domain Fronting, and I was blown away that Command & Control traffic could be exfiltrated out via HTTPS using legit domains like `ajax.microsoft.com`. It even uses Microsoft's TLS Certificates! Unfortunately for me, I began Red Teaming at the same time Domain Fronting died on Azure. Even though Domain Fronting on Azure was dead, there was still allot of awesome Red Team techniques that could be done with Azure. 

Steve introduced me to Azure Device Code Phishing. During this time I dived deep into Azure and the Microsoft Graph API for Red Teaming. We created the tool [TokenTactics](https://github.com/rvrsh3ll/TokenTactics), derived from the great work of [Dr. Nestori Syynimaa (@DrAzureAD)](https://twitter.com/DrAzureAD), and we made [The Art of the Device Code Phish](https://0xboku.com/2021/07/12/ArtOfDeviceCodePhish.html) blog if you are interested in our methodology.

While creating TokenTactics and experimenting with the MS Graph API, I discovered it was possible to use the Microsoft Graph API as a C2 channel. There are many different ways to use the MS Graph API as a C2 channel, and I am not the only person (or the first) to discover this. [VX-Underground](https://twitter.com/vxunderground), created by [@smelly__vx](https://twitter.com/smelly__vx) - the creator/publisher of the HellsGate technique, released information last month that [the North Korean Advanced Persistent Threat (APT) group "InkySquid" (AKA ScarCruft and APT37) uses the Microsoft Graph API for C2 operations](https://twitter.com/vxunderground/status/1429867158075498506). After releasing a teaser of this project on [Twitter](https://twitter.com/0xBoku/status/1435788324044640260) & [LinkedIn](https://www.linkedin.com/posts/bobby-cooke_azure-outlook-c2-activity-6841556676315901952-XIvN), several DFIR professionals commented that this technique of using the Microsoft Graph API for C2 operations is actively being used by ransomware groups in the wild, dating back months.

During the Red Team engagement, I attempted to get Cobalt Strike working with the MS Graph API as the C2 channel. Unfortunately, I failed, but this is still a future goal. The issue I face with getting this to work with Cobalt Strike, is that the MS Graph API uses 2 tokens for communications. The first token is the Refresh Token which can last up to 90 days. The second token, the Access Token, is a temporary token that last around an hour. Direct communications to the MS Graph API are done via authenticating with the Access Token. Once an Access Token expires, the Refresh Token can be used to get new Access Tokens. Since I am still new to Red Teaming & Cobalt Strike development, I could not figure out how to use the Cobalt Strike Malleable C2 profile to support constantly getting new Access Tokens and sending these changing Access Tokens in the `Authorization` header of HTTPS beacon's requests. Since releasing the teaser on Twitter, [Joe Vest](https://twitter.com/joevest), [Alfie Champion](https://twitter.com/ajpc500), and other rockstars of the community have given me some epic direction on how to get this to work with Cobalt Strike! Hopefully there will be a Cobalt Strike follow up to this project in the future ;) 

![](/assets/diagram.png)

### Implant Execution Flow
1. Get an Access Token to the MS Graph API using the hard-coded Refresh Token of the Attacker.
  + This is done via HTTPS TCP communications to the host `graph.microsoft.com`.
  + This traffic is encrypted using the TLS Certificate returned from the legitimate Microsoft web server.
  + The implant uses the `WinInet` Dynamic-link library for HTTPS communications.
  + The hard-coded Attacker Refresh Token should be good for 90 days. 
    + If the implant is compromised, the Attacker can revoke the hard-coded Refresh Token to restrict access from Malware Reverse Engineers. 
2. After the implant receives an Access Token for the Attackers MS Graph API, the implant enters an infinite loop.
  + If there is no internet connection or internet connection is disrupted during the loop, the implant will sleep for 3 minutes and try again.
  + The implant keeps track of time, and if 15 minutes has passed, it will get a new Access Token to continue communications.
3. The first task in the loop is to use the MS Graph API Access Token to access the Attackers Draft mailbox and read the most recent message for commands to execute on the compromised Windows device.
  + The Draft mailbox was chosen because this way there are no emails being sent via SMTP.
4. Once the command is received, it is parsed to determine which meta command it will execute. Currently there are 3 meta commands: `cmd`, `sleep`, `exit`
  + `cmd`: Takes the following string after the meta command and executes it by spawning a child process.
  + `sleep`: Takes the following word after the meta command and will change the implants sleep to the value supplied (in milliseconds).
  + `exit`: Exits/kills the host process.
5. If the meta command is `cmd` the implant will create a child process to execute the command, the child process will write its standard output to a pipe, the child process exits after command execution, and the host implant process will read the output of the child process via the pipe.
6. After the implant gets the output from the executed command, the implant will use the MS Graph API to create a new draft email which contains the command output.
7. The implant will then create a second draft email with a blank body.
  + This allows logging of the command output within the Attackers Draft mailbox.
  + This queues the Attacker with a fresh draft message to enter the next command the implant will execute.
8. After the command has been executed and the output returned to the Attacker, the implant will sleep for a time controlled by the attacker, and then repeat this loop.

## Instructions
1. Standup Red Team Azure Infrastructure that will be used as the Command & Control by following my blog post [The Art of the Device Code Phish](https://0xboku.com/2021/07/12/ArtOfDeviceCodePhish.html) to setup:
  + Azure Account Subscription
    + _When creating an Azure Account, help the Microsoft DFIR team by attributing your account to your Red Team organization. This helps save time for their team when they are investigating if you are a real threat, performing threat emulation services, or performing offensive security research._
    + _See [Nick Carr- Lead, Cyber Crime Intelligence / Investigations @Microsoft](https://twitter.com/ItsReallyNick/status/1290850096683388930) for more insight._
  + Azure Active Directory Tenant
  + Office 365 for Azure Active Directory
  + Create a user for the Outlook Command & Control mailbox
  + Install the [TokenTactics PowerShell Module](https://github.com/rvrsh3ll/TokenTactics)
2. Use TokenTactics to get the Tenant ID of the Azure AD you just created:
```powershell
PS C:\Users\boku\Desktop\TokenTactics-main> Import-Module .\TokenTactics.psd1
PS C:\Users\boku\Desktop\TokenTactics-main> Get-TenantID -domain theharvester.world
1d5551a0-f4f2-4101-9c3b-394247ec7e08
```
3. Add your TenantID to the `char tenantId[]` variable within the `azureOutlookC2.c` file.
4. Get an Azure Refresh Token by using TokenTactics to device code phish yourself with the C2 mailbox user:
```powershell
# Import the TokenTactics module into the PowerShell session
PS C:\Users\boku> cd .\TokenTactics
PS C:\Users\boku\TokenTactics> Import-Module .\TokenTactics.psd1
# Start a Device Code phish request to get a 'user_code'
PS C:\Users\boku\> Get-AzureToken -Client Graph
user_code        : ERDVDCNHH
```
5. Go to [microsoft.com/devicelogin](https://microsoft.com/devicelogin), enter the `user_code` from TokenTactics, and login with the C2 mailbox user.
6. In the PowerShell session running TokenTactics, copy the refresh token from the successful device code phish on yourself.
  + If you need more information on how TokenTactics works, please see [The Art of the Device Code Phish](https://0xboku.com/2021/07/12/ArtOfDeviceCodePhish.html)
7. Add your refresh token to the  `char refreshToken[]` variable within the `azureOutlookC2.c` file.
```c
void main() {
    // Variables
    char refreshToken[] = "0.AXwAoFFVHfL0AUGcOzlCR-x-CNYOWdOzUgJBrv-q0ikqsBx8ACA.AgABAAAAAA...
//                           ^Put your refresh token here and compile
```
8. Compile `azureOutlookC2.c`.
```bash
# Compile with x64 MinGW:
bobby.cooke$ cat compile.sh
x86_64-w64-mingw32-gcc -m64 -mwindows -Os azureOutlookC2.c -o azureOutlookC2.exe -lwininet
bobby.cooke$ bash compile.sh
```
9. Execute the `azureOutlookC2.exe` PE file on a Windows Device.
10. As the attacker from the attacker computer, open a browser, login to `outlook.office.com`, and control the Windows device running the implant from your mailbox.

## Initial Project Goals
+ Make a working proof of concept that uses the Microsoft Graph API for a C2 channel and control a computer from my email.

## What This Project Is
+ This project is a proof of concept, which demonstrates how an Attacker can use the Microsoft Graph API for C2 operations.
+ This project is intended for other offensive security researchers to learn from.
+ I have not personally come up with any great ways to defend or detect this C2 channel. My hope is that by supplying this to greater defender minds than myself, it will result in some awesome defensive techniques. 

## What This Project Isn't
+ This project itself is not a fully functional C2, ready for OPSEC safe engagements.

## Detection & Prevention Ideas from Defenders (To Add Please Submit a Pull Request )
### [Mehmet Ergene (@Cyb3rMonk)](https://twitter.com/Cyb3rMonk) Detection Advice
1. "Baselining applications connecting to Graph API and checking the anomalies might be an idea. Could be bypassed easily though."
2. "As always, [detecting beaconing traffic](https://t.co/gNWIpGbuty?amp=1). (I'll make an improvement to cover Graph API and similar stuff)"
### [F-Secure](https://www.f-secure.com/gb-en/consulting/our-thinking/rip-office365-command-and-control) - Shared from [Alfie Champion](https://twitter.com/ajpc500)
+ "Microsoft is an example of one such organization which has proactively taken steps to defend organizations from abuse of its services. It has recently developed the capability to detect and block malicious use of Azure Applications. Specifically, F-Secure has observed that any application used in the C3 framework (such as OneDrive365 and Outlook365 (O365) is now detected as malicious, and subsequently disabled by Microsoft (within approximately three hours)."

## Credits / References
+ [Sektor7 Malware Development Courses](https://institute.sektor7.net/red-team-operator-malware-development-essentials)
+ [@passthehashbrwn](https://twitter.com/passthehashbrwn) - [Dynamic payload generation with mingw](https://passthehashbrowns.github.io/dynamic-payload-generation-with-mingw)
+ Raphael Mudge - [Red Team Ops with Cobalt Strike (2 of 9): Infrastructure](https://www.youtube.com/watch?v=5gwEMocFkc0&t=1s)
+ Raphael Mudge - [Red Team Ops with Cobalt Strike (3 of 9): C2](https://www.youtube.com/watch?v=Z8n9bIPAIao)
+ [Microsoft Graph REST API v1.0](https://docs.microsoft.com/en-us/graph/api/user-post-messages?view=graph-rest-1.0&tabs=htt)
+ [Microsoft WinInet](https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-httpsendrequest)
+ [StackOverFlow - Create Process and Capture stdout](https://stackoverflow.com/questions/42402673/createprocess-and-capture-stdout)
+ [Microsoft - Creating a Child Process with Redirected Input and Output](https://docs.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output?redirectedfrom=MSD)

## Cool Projects/Research/Blogs That are Similar
#### F-Secure C3 - Custom Command & Control
+ "C3 was built in response to this requirement. It is a tool that allows Red Teams to rapidly develop and utilise esoteric command and control channels (C2)."
+ [RIP OFFICE365 COMMAND AND CONTROL – WE HARDLY KNEW YOU](https://www.f-secure.com/gb-en/consulting/our-thinking/rip-office365-command-and-control)
+ [ F-Secure C3 - Custom Command & Control GitHub Repo](https://github.com/FSecureLABS/C3)
#### Callidus by [Chirag Savla](https://twitter.com/chiragsavla94)
+ "It (Callidus) is developed using .net core framework in C# language. Allows operators to leverage O365 services for establishing command & control communication channel. It usages Microsoft Graph APIs for communicating with O365 services."
+ [3xpl01tc0d3r/Callidus GitHub Repo](https://github.com/3xpl01tc0d3r/Callidus)
+ [Introduction to Callidus - Blog Post](https://3xpl01tc0d3r.blogspot.com/2020/03/introduction-to-callidus.html)
#### Azure Application Proxy C2 - [Adam Chester (@\_xpn\_)](https://twitter.com/\_xpn\_)
+ [Azure Application Proxy C2 - Research Blog](https://blog.xpnsec.com/azure-application-proxy-c2/)
