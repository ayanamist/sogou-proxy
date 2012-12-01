import ctypes
from ctypes import windll
from ctypes import wintypes

GROUP = ctypes.c_uint
SOCKET = ctypes.c_uint
NULL = ctypes.c_ulong()
FALSE = 0
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1)
NULL_HANDLE = wintypes.HANDLE(0)

WAIT_TIMEOUT = 258
ERROR_IO_PENDING = 997

NONE = 0
READ = 0x001
WRITE = 0x004
ERROR = 0x008 | 0x010

class _US(ctypes.Structure):
    _fields_ = [
        ("Offset", wintypes.DWORD),
        ("OffsetHigh", wintypes.DWORD),
    ]


class _U(ctypes.Union):
    _fields_ = [
        ("s", _US),
        ("Pointer", ctypes.c_void_p),
    ]
    _anonymous_ = ("s",)


class OVERLAPPED(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.POINTER(wintypes.ULONG)),
        ("InternalHigh", ctypes.POINTER(wintypes.ULONG)),
        ("u", _U),
        ("hEvent", wintypes.HANDLE),
    ]
    _anonymous_ = ("u",)

class OVERLAPPED_ENTRY(ctypes.Structure):
    _fields_ = [
        ("lpCompletionKey", ctypes.POINTER(wintypes.ULONG)),
        ("lpOverlapped", ctypes.POINTER(OVERLAPPED)),
        ("Internal", ctypes.POINTER(wintypes.ULONG)),
        ("dwNumberOfBytesTransferred", wintypes.DWORD),
    ]

class WSABUF(ctypes.Structure):
    _fields_ = [
        ("len", ctypes.c_ulong),
        ("buf", ctypes.c_char_p),
    ]

currentCompletionKey = 0L
ulCount = 16

WSASocket = windll.Ws2_32.WSASocketA
WSASocket.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_void_p, GROUP, wintypes.DWORD)
WSASocket.restype = SOCKET

WSACleanup = windll.Ws2_32.WSACleanup
WSACleanup.argtypes = ()
WSACleanup.restype = ctypes.c_int

WSAGetLastError = windll.Ws2_32.WSAGetLastError

CloseHandle = windll.kernel32.CloseHandle
CloseHandle.argtypes = (wintypes.HANDLE,)
CloseHandle.restype = wintypes.BOOL

CreateIoCompletionPort = windll.kernel32.CreateIoCompletionPort
CreateIoCompletionPort.argtypes = (wintypes.HANDLE, wintypes.HANDLE, ctypes.c_ulong, wintypes.DWORD)
CreateIoCompletionPort.restype = wintypes.HANDLE

GetQueuedCompletionStatus = windll.kernel32.GetQueuedCompletionStatus
GetQueuedCompletionStatus.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(ctypes.c_ulong),
                                      ctypes.POINTER(ctypes.POINTER(OVERLAPPED)), wintypes.DWORD)
GetQueuedCompletionStatus.restype = wintypes.BOOL

GetQueuedCompletionStatusEx = windll.kernel32.GetQueuedCompletionStatusEx
GetQueuedCompletionStatusEx.argtypes = (wintypes.HANDLE, ctypes.POINTER(ctypes.ARRAY(OVERLAPPED_ENTRY, ulCount)),
                                        ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong), wintypes.DWORD, wintypes.BOOL)
GetQueuedCompletionStatusEx.restype = wintypes.BOOL


def CreateCompletionKey():
    global currentCompletionKey
    v = currentCompletionKey
    currentCompletionKey += 1L
    return v


class Error(IOError):
    pass


class IOCP(object):
    def __init__(self):
        self._hIOCP = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL_HANDLE, NULL, NULL)
        if self._hIOCP == 0:
            err = WSAGetLastError()
            WSACleanup()
            raise Error(err)
        self._ov_map_by_key = {}
        self._ov_map_by_fd = {}
        self._evt_map = {}

    def close(self):
        CloseHandle(self._hIOCP)
        WSACleanup()

    def register(self, fd, events):
        ovKey = CreateCompletionKey()
        ret = CreateIoCompletionPort(fd, self._hIOCP, ovKey, NULL)
        if ret == FALSE:
            err = WSAGetLastError()
            raise Error(err)
        self._ov_map_by_key[ovKey] = fd
        self._ov_map_by_fd[fd] = ovKey
        if fd in self._evt_map:
            raise IOError("fd %d already registered" % fd)
        self._evt_map[fd] = events

    def modify(self, fd, events):
        self.unregister(fd)
        self.register(fd, events)

    def unregister(self, fd):
        del self._evt_map[fd]
        ovKey = self._ov_map_by_fd[fd]
        del self._ov_map_by_fd[fd]
        del self._ov_map_by_key[ovKey]

    def poll(self, timeout):
        ulNumEntriesRemoved = ctypes.c_ulong()
        lpCompletionPortEntries = ctypes.ARRAY(OVERLAPPED_ENTRY, ulCount)()

        ret = GetQueuedCompletionStatusEx(self._hIOCP, ctypes.byref(lpCompletionPortEntries), ulCount,
            ctypes.byref(ulNumEntriesRemoved), int(timeout * 1000), FALSE)
        results = []
        if ret == FALSE:
            err = WSAGetLastError()
            if err == WAIT_TIMEOUT:
                return results
            else:
                raise Error(err)
        for i in xrange(int(ulNumEntriesRemoved.value)):
            completionKey = lpCompletionPortEntries[i].lpCompletionKey
            ovKey = completionKey.value
            if ovKey in self._ov_map_by_key:
                fd = self._ov_map_by_key[ovKey]
                results.append((fd, self._evt_map[fd]))
        return results
