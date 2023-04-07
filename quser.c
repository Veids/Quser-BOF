#include <windows.h>
#include <wtsapi32.h>
#include "beacon.h"

DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetLastError (void);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$FileTimeToSystemTime (const FILETIME*, LPSYSTEMTIME);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetCurrentProcessId (void);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$ProcessIdToSessionId (DWORD dwProcessId, DWORD *pSessionId);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetTickCount (void);

DECLSPEC_IMPORT BOOL __cdecl USER32$GetLastInputInfo (PLASTINPUTINFO);

DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI WTSAPI32$WTSOpenServerA (LPSTR);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI WTSAPI32$WTSEnumerateSessionsA (HANDLE, DWORD, DWORD, PWTS_SESSION_INFOA *, DWORD *);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI WTSAPI32$WTSQuerySessionInformationA (HANDLE, DWORD, WTS_INFO_CLASS, LPSTR *, DWORD *);
DECLSPEC_IMPORT WINBASEAPI void WINAPI WTSAPI32$WTSFreeMemory (PVOID);
DECLSPEC_IMPORT WINBASEAPI void WINAPI WTSAPI32$WTSCloseServer (HANDLE);

DECLSPEC_IMPORT int __cdecl MSVCRT$strcmp(const char*, const char*);

DWORD getLastInput(DWORD currentSessionId){
	DWORD processId = KERNEL32$GetCurrentProcessId();	
	DWORD sessionId = 0;
	if(!KERNEL32$ProcessIdToSessionId(processId, &sessionId))
		return -1;

	if(sessionId != currentSessionId)
		return -1;

	LASTINPUTINFO lii;
	lii.cbSize = sizeof(LASTINPUTINFO);

	if(!USER32$GetLastInputInfo(&lii))
		return -1;

	DWORD elapsed = KERNEL32$GetTickCount() - lii.dwTime;

	return elapsed;
}

void go(char * args, int alen)
{	
	datap parser;
	PWTS_SESSION_INFOA pwsi;
	DWORD dwCount = 0;
	DWORD bytesReturned = 0;
	BeaconDataParse(&parser, args, alen);
	char *targetHost = BeaconDataExtract(&parser, NULL);
	char *addrFamily = "";
	char *stateInfo = "";
	HANDLE hTarget = NULL;
	LPTSTR userName, userDomain, clientName, clientAddress, wtsinfo;
	PWTS_CLIENT_ADDRESS clientAddressStruct = NULL;
	PWTSINFO wtsinfoStruct = NULL;
	BOOL successGetSession = 0;
	hTarget = WTSAPI32$WTSOpenServerA(targetHost);
	successGetSession = WTSAPI32$WTSEnumerateSessionsA(hTarget, 0, 1, &pwsi, &dwCount);
	if(!successGetSession){
		if(KERNEL32$GetLastError()==5)
			BeaconPrintf(CALLBACK_OUTPUT, "Access denied: Could not connect to %s.", targetHost);
		else
			BeaconPrintf(CALLBACK_OUTPUT, "ERROR %d: Could not connect to %s.", KERNEL32$GetLastError(), targetHost);
	} else {
		BeaconPrintf(CALLBACK_OUTPUT, "%-20s%-25s%-15s%-15s%-15s%-18s%-20s%s\n", "UserDomain", "UserName", "SessionName", "SessionID" , "State", "SourceAddress", "SourceClientName", "IdleTime");
		for (unsigned int i = 0; i < dwCount; i++)
		{
			WTS_SESSION_INFO si = pwsi[i];
			if(si.SessionId > 2048 || si.SessionId < 0)
				continue;
			BOOL getResult;
			getResult = WTSAPI32$WTSQuerySessionInformationA(hTarget, si.SessionId, WTSUserName, &userName, &bytesReturned);
			if(!getResult){
				userName = "N/A";
				BeaconPrintf(CALLBACK_ERROR, "ERROR %d on getting attribute using WTSQuerySessionInformationA", KERNEL32$GetLastError());
			}
			getResult = WTSAPI32$WTSQuerySessionInformationA(hTarget, si.SessionId, WTSDomainName, &userDomain, &bytesReturned);
			if(!getResult){
				userDomain = "N/A";
				BeaconPrintf(CALLBACK_ERROR, "ERROR %d on getting attribute using WTSQuerySessionInformationA", KERNEL32$GetLastError());
			}
			getResult = WTSAPI32$WTSQuerySessionInformationA(hTarget, si.SessionId, WTSClientName, &clientName, &bytesReturned);
			if(!getResult){
				clientName = "N/A";
				BeaconPrintf(CALLBACK_ERROR, "ERROR %d on getting attribute using WTSQuerySessionInformationA", KERNEL32$GetLastError());
			}
			getResult = WTSAPI32$WTSQuerySessionInformationA(hTarget, si.SessionId, WTSClientAddress, &clientAddress, &bytesReturned);
			if(!getResult){
				clientAddress = "N/A";
				BeaconPrintf(CALLBACK_ERROR, "ERROR %d on getting attribute using WTSQuerySessionInformationA", KERNEL32$GetLastError());
			}
			clientAddressStruct = (PWTS_CLIENT_ADDRESS)clientAddress;
			if(clientAddressStruct->AddressFamily == 0)
				addrFamily = "Unspecified";
			else if(clientAddressStruct->AddressFamily == 2)
				addrFamily = "InterNetwork";
			else if(clientAddressStruct->AddressFamily == 17)
				addrFamily = "NetBios";
			else 
				addrFamily = "Unknown";

			LARGE_INTEGER idle;
			SYSTEMTIME idleTime;
			getResult = WTSAPI32$WTSQuerySessionInformationA(hTarget, si.SessionId, WTSSessionInfo, &wtsinfo, &bytesReturned);
			if(!getResult){
				BeaconPrintf(CALLBACK_ERROR, "ERROR %d on getting attribute using WTSQuerySessionInformationA", KERNEL32$GetLastError());
			} else {
				wtsinfoStruct = (PWTSINFO)wtsinfo;

				idle = wtsinfoStruct->CurrentTime;
				idle.QuadPart -= wtsinfoStruct->LastInputTime.QuadPart;

				FILETIME LclFileTime = { idle.LowPart, idle.HighPart };
				getResult = KERNEL32$FileTimeToSystemTime(&LclFileTime, &idleTime);
				if(!getResult){
					clientAddress = "N/A";
					BeaconPrintf(CALLBACK_ERROR, "ERROR %d on converting time using FileTimeToSystemTime", KERNEL32$GetLastError());
				}
			}

			if(strlen(userName)){
				if(si.State == WTSActive)
					stateInfo = "Active";
				else if(si.State == WTSConnected)
					stateInfo = "Connected";
				else if(si.State == WTSDisconnected)
					stateInfo = "Disconnected";
				else if(si.State == WTSIdle)
					stateInfo = "Idle";
				else 
					stateInfo = "Unknown";
				if(MSVCRT$strcmp(addrFamily, "Unspecified") == 0){
						DWORD durationInMillis = getLastInput(si.SessionId);
						if(durationInMillis == -1) {
							BeaconPrintf(CALLBACK_OUTPUT, "%-20s%-25s%-15s%-15i%-15s%-18s%-20s%s\n", userDomain, userName, si.pWinStationName, si.SessionId, stateInfo, "-", "-", "-");
						} else {
							long seconds = (durationInMillis / 1000) % 60;
							long minutes = (durationInMillis / (1000 * 60)) % 60;
							long hours = (durationInMillis / (1000 * 60 * 60)) % 24;
							BeaconPrintf(CALLBACK_OUTPUT, "%-20s%-25s%-15s%-15i%-15s%-18s%-20s%dh %dm %ds\n", userDomain, userName, si.pWinStationName, si.SessionId, stateInfo, "-", "-", hours, minutes, seconds);
						}
				}
				else if(!getResult)
					BeaconPrintf(CALLBACK_OUTPUT, "%-20s%-25s%-15s%-15i%-15s%u.%u.%u.%-6u%s\n", userDomain, userName, si.pWinStationName, si.SessionId, stateInfo, clientAddressStruct->Address[2], clientAddressStruct->Address[3], clientAddressStruct->Address[4], clientAddressStruct->Address[5], clientName);
				else 
					BeaconPrintf(CALLBACK_OUTPUT, "%-20s%-25s%-15s%-15i%-15s%u.%u.%u.%-6u%-20s%dh %dm %ds\n", userDomain, userName, si.pWinStationName, si.SessionId, stateInfo, clientAddressStruct->Address[2], clientAddressStruct->Address[3], clientAddressStruct->Address[4], clientAddressStruct->Address[5], clientName, idleTime.wHour, idleTime.wMinute, idleTime.wSecond);
			}
		}
	}
	WTSAPI32$WTSFreeMemory(pwsi);
	WTSAPI32$WTSCloseServer(hTarget);
};
