#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

const ULONG SE_DEBUG_PRIVILEGE = 20;
const ULONG SE_SHUTDOWN_PRIVILEGE = 19;

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWCH   Buffer;
}UNICODE_STRING, *PUNICODE_STRING;

typedef enum _PROCESSINFOCLASS
{
	ProcessBasicInformation,           //0
	ProcessQuotaLimits,                //1
	ProcessIoCounters,                 //2
	ProcessVmCounters,                 //3
	ProcessTimes,                      //4
	ProcessBasePriority,               //5
	ProcessRaisePriority,              //6
	ProcessDebugPort,                  //7 
	ProcessExceptionPort,              //8
	ProcessAccessToken,                //9
	ProcessLdtInformation,             //10
	ProcessLdtSize,                    //11
	ProcessDefaultHardErrorMode,       //12
	ProcessIoPortHandlers,             //13
	ProcessPooledUsageAndLimits,       //14
	ProcessWorkingSetWatch,            //15
	ProcessUserModeIOPL,               //16 
	ProcessEnableAlignmentFaultFixup,  //17
	ProcessPriorityClass,              //18
	ProcessWx86Information,            //19
	ProcessHandleCount,                //20
	ProcessAffinityMask,               //21
	ProcessPriorityBoost,              //22
	ProcessDeviceMap,                  //23
	ProcessSessionInformation,         //24
	ProcessForegroundInformation,      //25
	ProcessWow64Information,           //26
	ProcessImageFileName,              //27
	ProcessLUIDDeviceMapsEnabled,      //28
	ProcessBreakOnTermination,         //29  0x1D
	ProcessDebugObjectHandle,          //30
	ProcessDebugFlags,                 //31
	ProcessHandleTracing,              //32
	ProcessIoPriority,                 //33
	ProcessExecuteFlags,               //34
	ProcessTlsInformation,             //35
	ProcessCookie,                     //36
	ProcessImageInformation,           //37
	ProcessCycleTime,                  //38
	ProcessPagePriority,               //39
	ProcessInstrumentationCallback,    //40
	ProcessThreadStackAllocation,      //41
	ProcessWorkingSetWatchEx,          //42
	ProcessImageFileNameWin32,         //43
	ProcessImageFileMapping,           //44
	ProcessAffinityUpdateMode,         //45
	ProcessMemoryAllocationMode,       //46
	MaxProcessInfoClass                //47
} PROCESSINFOCLASS;

typedef enum _THREADINFOCLASS
{
	ThreadBasicInformation,             //0
	ThreadTimes,                        //1
	ThreadPriority,                     //2
	ThreadBasePriority,                 //3
	ThreadAffinityMask,                 //4
	ThreadImpersonationToken,           //5
	ThreadDescriptorTableEntry,         //6
	ThreadEnableAlignmentFaultFixup,    //7
	ThreadEventPair_Reusable,           //8
	ThreadQuerySetWin32StartAddress,    //9
	ThreadZeroTlsCell,                  //10
	ThreadPerformanceCount,             //11
	ThreadAmILastThread,                //12
	ThreadIdealProcessor,               //13
	ThreadPriorityBoost,                //14
	ThreadSetTlsArrayAddress,           //15
	ThreadIsIoPending,                  //16
	ThreadHideFromDebugger,             //17
	ThreadBreakOnTermination,           //18   0x12
	ThreadSwitchLegacyState,            //19
	ThreadIsTerminated,                 //20
	ThreadLastSystemCall,               //21
	ThreadIoPriority,                   //22
	ThreadCycleTime,                    //23
	ThreadPagePriority,                 //24
	ThreadActualBasePriority,           //25
	ThreadTebInformation,               //26
	ThreadCSwitchMon,                   //27
	MaxThreadInfoClass                  //28
} THREADINFOCLASS;



typedef enum _HARDERROR_RESPONSE_OPTION
{
	OptionAbortRetryIgnore,
	OptionOk,
	OptionOkCancel,
	OptionRetryCancel,
	OptionYesNo,
	OptionYesNoCancel,
	OptionShutdownSystem
} HARDERROR_RESPONSE_OPTION, *PHARDERROR_RESPONSE_OPTION;

typedef enum _HARDERROR_RESPONSE
{
	ResponseReturnToCaller,
	ResponseNotHandled,
	ResponseAbort,
	ResponseCancel,
	ResponseIgnore,
	ResponseNo,
	ResponseOk,
	ResponseRetry,
	ResponseYes
} HARDERROR_RESPONSE, *PHARDERROR_RESPONSE;


HARDERROR_RESPONSE Response;
HARDERROR_RESPONSE_OPTION ResponseOption = OptionShutdownSystem;


// ����ָ��
typedef NTSTATUS(NTAPI *NTRAISEHARDERROR)(
	IN NTSTATUS             ErrorStatus,
	IN ULONG                NumberOfParameters,
	IN PUNICODE_STRING      UnicodeStringParameterMask OPTIONAL,
	IN PVOID                *Parameters,
	IN HARDERROR_RESPONSE_OPTION ResponseOption,
	OUT PHARDERROR_RESPONSE Response
	);

typedef NTSTATUS(__cdecl *RTLSETPROCESSISCRITICAL)(IN BOOLEAN NewValue, OUT PBOOLEAN OldValue OPTIONAL, IN BOOLEAN NeedBreaks);
typedef NTSTATUS(__cdecl *RTLSETTHREADISCRITICAL)(IN BOOLEAN NewValue, OUT PBOOLEAN OldValue OPTIONAL, IN BOOLEAN NeedBreaks);

typedef NTSYSCALLAPI NTSTATUS(WINAPI *NTSETINFORMATIONPROCESS)(
	IN HANDLE               ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	IN PVOID                ProcessInformation,
	IN ULONG                ProcessInformationLength
	);

typedef NTSYSCALLAPI NTSTATUS(WINAPI *NTSETINFORMATIONTHREAD)(
	HANDLE ThreadHandle,
	THREADINFOCLASS ThreadInformationClass,
	PVOID ThreadInformation,
	ULONG ThreadInformationLength
	);

typedef BOOL(NTAPI *RTLADJUSTPRIVILEGE)(ULONG, BOOL, BOOL, PBOOLEAN);

typedef NTSTATUS(NTAPI *pfNtQueryInformationThread)(
	HANDLE           ThreadHandle,
	THREADINFOCLASS ThreadInformationClass,
	PVOID            ThreadInformation,
	ULONG            ThreadInformationLength,
	PULONG           ReturnLength
	);

NTRAISEHARDERROR NtRaiseHardError;
RTLSETPROCESSISCRITICAL RtlSetProcessIsCritical;
RTLSETTHREADISCRITICAL RtlSetThreadIsCritical;
NTSETINFORMATIONPROCESS NtSetInformationProcess;
NTSETINFORMATIONTHREAD NtSetInformationThread;
RTLADJUSTPRIVILEGE RtlAdjustPrivilege;
pfNtQueryInformationThread NtQueryInformationThread;


// ����ʵ��
BOOL BSoD_R3();

// ��ӡ���ܱ�
VOID PrintInfo();

DWORD Index = -1;

int main(int argc, char *argv[], char *envp[])
{
	PrintInfo();
	BSoD_R3();
	return 0;
}


VOID PrintInfo()
{
	printf("1.NtRaiseHardError\n");
	printf("2.RtlSetProcessIsCritical\n");
	printf("3.NtSetInformationProcess\n");
	printf("4.RtlSetThreadIsCritical\n");
	printf("5.NtSetInformationThread\n");
	printf("0.Exit\n");
	printf("Please input the number��");
	scanf("%d", &Index);
	if (Index < 0 || Index > 5)
	{
		printf("Please input the right number\n");
	}
	if (!Index)
	{
		ExitProcess(0);
	}
}
// ��ȡ������ַ
void GetFunction()
{
	// ��ȡntdll��ַ
	HMODULE  NtBase = GetModuleHandle(TEXT("ntdll.dll"));
	if (!NtBase)
	{
		printf("Get NtBase Failed\n");
		return;
	}

	// ��ȡ��������ַ
	NtRaiseHardError = (NTRAISEHARDERROR)GetProcAddress(NtBase, "NtRaiseHardError");
	RtlSetProcessIsCritical = (RTLSETPROCESSISCRITICAL)GetProcAddress(NtBase, "RtlSetProcessIsCritical");
	RtlSetThreadIsCritical = (RTLSETTHREADISCRITICAL)GetProcAddress(NtBase, "RtlSetThreadIsCritical");
	NtSetInformationThread = (NTSETINFORMATIONTHREAD)GetProcAddress(NtBase, "NtSetInformationThread");
	NtSetInformationProcess = (NTSETINFORMATIONPROCESS)GetProcAddress(NtBase, "NtSetInformationProcess");
	RtlAdjustPrivilege = (RTLADJUSTPRIVILEGE)GetProcAddress(NtBase, "RtlAdjustPrivilege");
	NtQueryInformationThread = (pfNtQueryInformationThread)GetProcAddress(NtBase, "NtQueryInformationThread");

	do
	{
		if (!NtRaiseHardError)
		{
			printf("GetAddrssFailed:NtRaiseHardError\n");
			break;
		}
		if (!RtlSetProcessIsCritical)
		{
			printf("GetAddrssFailed:RtlSetProcessIsCritical\n");
			break;
		}
		if (!RtlSetThreadIsCritical)
		{
			printf("GetAddrssFailed:RtlSetThreadIsCritical\n");
			break;
		}
		if (!NtSetInformationThread)
		{
			printf("GetAddrssFailed:NtSetInformationThread\n");
			break;
		}
		if (!NtSetInformationProcess)
		{
			printf("GetAddrssFailed:NtSetInformationProcess\n");
			break;
		}
		if (!NtQueryInformationThread)
		{
			printf("GetAddrssFailed:NtQueryInformationProcess\n");
			break;
		}

	} while (FALSE);

	return;
}
BOOL BSoD_R3()
{
	NTSTATUS status;
	BOOLEAN A;
	BOOL Enable = TRUE;

	GetFunction();

	// ��ȡDebugȨ��
	if (Index > 1 && RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &A))
	{
		printf("------Please run program as an Administrator------\n");
		system("pause");
		return FALSE;
	}

	switch (Index)
	{
	case 1:
		RtlAdjustPrivilege(SE_SHUTDOWN_PRIVILEGE, TRUE, FALSE, &A);
		status = NtRaiseHardError(0xC0000999, 0, 0, 0, ResponseOption, &Response);
		break;
	case 2:
		status = RtlSetProcessIsCritical(TRUE, NULL, FALSE);
		ExitProcess(0);
		break;
	case 3:
		status = NtSetInformationProcess(GetCurrentProcess(), ProcessBreakOnTermination, &Enable, sizeof(Enable));
		ExitProcess(0);
		break;
	case 4:
		status = RtlSetThreadIsCritical(TRUE, NULL, FALSE);
		TerminateThread(GetCurrentThread(), 0);
		break;
	case 5:
		/*
		// ������գ��ÿ���ӵ������ʱ�̵����н��̺��߳���Ϣ
		HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);

		THREADENTRY32 te32;
		// ��ʹ�� Thread32First ǰ��ʼ�� THREADENTRY32 �Ľṹ��С.
		te32.dwSize = sizeof(THREADENTRY32);

		// ��ȡ��һ���߳�
		if (Thread32First(Snapshot, &te32))
		{
		ULONG PID = GetCurrentProcessId();
		HANDLE ThreadHandle = NULL;
		te32.dwSize = sizeof(te32);
		do
		{
		ThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
		// ����߳����ڱ�����  ��������ΪCritical Thread
		if (PID == te32.th32OwnerProcessID)
		{
		NTSTATUS status = NtSetInformationThread(ThreadHandle, ThreadBreakOnTermination, &Enable, sizeof(Enable));
		printf("�߳�IDΪ%X\n", te32.th32ThreadID);
		}
		// ֱ�������������߳�
		} while (Thread32Next(Snapshot, &te32));
		}
		ExitProcess(0);
		*/
		status = NtSetInformationThread(GetCurrentThread(), ThreadBreakOnTermination, &Enable, sizeof(Enable));
		TerminateThread(GetCurrentThread(), 0);
		break;
	}
	system("pause");
	return TRUE;
}