COMMENT @
    Useful structures for the program that aren't
    in masm32 normal headers
@


WSAData STRUCT
    wVersion        WORD  0
    wHighVersion    WORD  0
    szDescription   BYTE  257 dup(0)
    szSystemStatus  BYTE  129 dup(0)
    iMaxSockets     WORD  0
    iMaxUdpDg       WORD  0
    lpVendorInfo    DWORD 0
WSAData ENDS

addrinfo STRUCT
    ai_flags        DWORD   0
    ai_family       DWORD   0
    ai_socktype     DWORD   0
    ai_protocol     DWORD   0
    ai_addrlen      DWORD   0
    ai_canonname    DWORD   0
    ai_addr         DWORD   0 ; sockaddr struct
    ai_next         DWORD   0 ; addrinfo struct
addrinfo ENDS

sockaddr STRUCT
    sa_family       WORD    0
    sa_data         BYTE    14 dup(0)
sockaddr ENDS

STARTUPINFO STRUCT
    cb              DWORD   0
    lpReserved      DWORD   0 ; LPTSTR
    lpDesktop       DWORD   0 ; LPTSTR
    lpTitle         DWORD   0 ; LPTSTR
    dwX             DWORD   0
    dwY             DWORD   0
    dwXSize         DWORD   0
    dwYSize         DWORD   0
    dwXCountChars   DWORD   0
    dwYCountChars   DWORD   0
    dwFillAttribute DWORD   0
    dwFlags         DWORD   0
    wShowWindow     WORD    0
    cbReserved2     WORD    0
    lpReserved2     DWORD   0 ; LPBYTE
    hStdInput       DWORD   0
    hStdOutput      DWORD   0
    hStdError       DWORD   0
STARTUPINFO ENDS

PROCESS_INFORMATION STRUCT
    hProcess        DWORD 0 ; HANDLE
    hThread         DWORD 0 ; HANDLE
    dwProcessId     DWORD 0
    dwThreadId      DWORD 0
PROCESS_INFORMATION ENDS
