junk_code_1 macro ___xxx
    local s1,s2,s3,s4,junk
    push ___xxx
    mov ebx, ecx
    xor ecx,ecx
    jz s3
s1:
    xchg ebx, [esp]
    xchg eax, ebx
    add esp,4
    jo s2
    jmp s4
s2:
    add ecx, ecx
    add ebx, edx
    sub ecx, ebx
    call junk
junk:
    add esp,4
    jmp s4
s3:
    add ecx, 69h
    add ebx, 69h
    mov ___xxx, ebx
    add ___xxx, ecx
    push eax
    jmp s1
s4:
    pop ___xxx
endm

junk_code_2 macro
    local badjunk
badjunk:
    MOV AX, 200
    ADD AX, 300
    MOV CX,300
    SUB ECX,100
    MOV AH, 02H
    MOV AX, 30
    MOV BX, 8
    ADD CX, 1
    MUL BX
    MOV AX, 30
    MOV BX, 12
    SUB CX, 1
    DIV BX
    loop badjunk
endm


junk_code_3 macro ___xxx
    local s1,s2,s3,s4,junk
    sub esp, 4
    mov [esp], ___xxx
    push ebx
    xor ebx, ecx 
    xor ecx, ebx 
    xor ebx, ecx
    pop ebx
    sub ebx, ecx
    jz s3
s1:
    xchg ebx, [esp]
    xchg eax, ebx
    add esp,4
    jo s2
    jmp s4
s2:
    add ecx, ecx
    add ebx, edx
    mov eax, 40201234h
    sub ecx, ebx
    call junk
junk:
    add esp,4
    jmp s4
s3:
    add ecx, 69h
    add ebx, 69h
    mov ___xxx, ebx
    add ___xxx, ecx
    push eax
    jmp s1
s4:
    mov ___xxx, [esp]
    add esp, 4
endm
