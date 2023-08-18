.386                    ;32-Bit Windows Assembly: Ep.2 – Windows APIs and Structs
.model flat, stdcall 
option casemap:none

extern  GetStdHandle@4:PROC                    
extern  WriteConsoleA@20:PROC                  
extern  ExitProcess@4:PROC                      
extern  GetCommandLineW@0: PROC
extern  CommandLineToArgvW@8:PROC
extern  WideCharToMultiByte@32:PROC 
extern  LocalFree@4:PROC

C_SIZE = 10000

.data                                                  



Msg1    db "Grandoreiro Malware decoder v1.1 @Dkavalanche 2023",13, 10, 0  ;  
Msg2    db "usage: decoder.exe chipertext key",0 ; 
buffer BYTE C_SIZE DUP(?); 
plain  BYTE C_SIZE DUP(?); 
ArgCipher BYTE C_SIZE DUP(?); 
ArgKey    BYTE C_SIZE DUP(?); 
lenc   DWORD ?
BytesWritten dd  ?                            
szArglist dd ?



 
.code                           
main PROC                              
   
;-----------Comprobacion de parametros ingresados--------------------

;https://stackoverflow.com/questions/44233484/masm32-x86-windows-assembly-getcommandlinetoargvw
;https://masm32.com/board/index.php?topic=7717.0

    ; Obtener la línea de comandos
    call GetCommandLineW@0
    mov esi, eax ; Guardar el puntero a la línea de comandos en esi

    lea ecx, dword ptr[ebp - 4] ; Get the current address of [ebp-4]
    push ecx                    ; int *pNumArgs (Pointer to a SDWORD, here at ebp-4)
    push eax                    ; LPCWSTR lpCmdLine (from GetCommandLineW)
    call CommandLineToArgvW@8

    mov [szArglist], eax        ; Store the result of CommandLineToArgvW (at least for LocalFree)

    mov esi, eax                ; ESI = address of a pointer (the first element in szArglist)
    mov ebx, [ebp-4]            ; Countdown the number of arguments
    cmp ebx, 3
    jb Error 
  
 Argumentos:                         

    ; https://msdn.microsoft.com/library/windows/desktop/dd374130.aspx
    push 0                               ; LPBOOL  lpUsedDefaultChar
    push 0                               ; LPCSTR  lpDefaultChar
    push SIZEOF ArgCipher                ; int     cbMultiByte
    push OFFSET ArgCipher                ; LPSTR   lpMultiByteStr
    push -1                              ; int     cchWideChar
    push [esi+4]                         ; LPCWSTR lpWideCharStr (dereferenced esi) ( cada arg es +4)
    push 0                               ; DWORD   dwFlags
    push 0                               ; UINT    CodePage
    call WideCharToMultiByte@32          ;convierte nombres largos a ANSI

    push 0                               ; LPBOOL  lpUsedDefaultChar
    push 0                               ; LPCSTR  lpDefaultChar
    push SIZEOF ArgKey                   ; int     cbMultiByte
    push OFFSET ArgKey                   ; LPSTR   lpMultiByteStr
    push -1                              ; int     cchWideChar
    push [esi+8]                           ; LPCWSTR lpWideCharStr (dereferenced esi) ( cada arg es +4)
    push 0                               ; DWORD   dwFlags
    push 0                               ; UINT    CodePage
    call WideCharToMultiByte@32          ;convierte nombres largos a ANSI

    push dword ptr [szArglist]
    call LocalFree@4                     ; Free the memory occupied by CommandLineToArgvW

    xor     eax, eax
    lea     ecx, offset ArgCipher   

LenCipher:

    add     eax, 1    
    add     ecx, 1     
    mov     edx, [ecx] 
    cmp     edx, 0     ; compare with zero
    je      LenCipherEnd     
    jmp     LenCipher     

LenCipherEnd:
    sar eax, 1
    dec eax
    mov [lenc], eax 


;-----------Convertir ciphertext a hexadecimal------------------------
mov esi, OFFSET ArgCipher
mov edi, OFFSET buffer  ;
call convertLoop
push offset buffer
;-----------Desencriptar buffer con key -----------------------------
mov esi, offset ArgKey ; Obtener el puntero a la clave
mov edi, offset buffer; Obtener el puntero al texto cifrado
call decrypt


;-----------------------------------------------Imprimir Texto Decoded---------------------------------

push  -11                                                      
    call    GetStdHandle@4                                       
    push    0                                                  
    push    offset BytesWritten                                   
    push    lenc     
    push    offset plain                                                                         
    push    eax                                                  
    call    WriteConsoleA@20              

jmp ExitNow

Error:

push  -11                                                      
    call    GetStdHandle@4                                       
    push    0                                                  
    push    offset BytesWritten                                   
    push    lengthof  Msg1    
    push    offset    Msg1                                                                        
    push    eax                                                  
    call    WriteConsoleA@20              

push  -11                                                      
    call    GetStdHandle@4                                       
    push    0                                                  
    push    offset BytesWritten                                   
    push    lengthof  Msg2    
    push    offset    Msg2                                                                        
    push    eax                                                  
    call    WriteConsoleA@20     

ExitNow:
push 0
call    ExitProcess@4
;--------------------------RUTINA DE CONVERTIR TEXT2HEX------------------------------------------------
convertLoop:
    push esi
    push edi
    xor ebx, ebx 
    xor ecx, ecx 
    xor edx, edx 
convertLoop1:
    movzx eax, BYTE PTR [esi]  ; Obtener el siguiente carácter hexadecimal
    cmp al, '0'  ; Comprobar si es un dígito hexadecimal válido
    jl convertEnd
    cmp al, '9'
    jg convertLetter
    
    sub al, '0'  ; Convertir dígito hexadecimal a valor numérico
    jmp convertNext
convertLetter:
    sub al, 'A'  ; Convertir letra hexadecimal a valor numérico
    add al, 10
convertNext:
    shl ebx, 4   ; Desplazar el contenido de ebx hacia la izquierda
    or ebx, eax  ; Realizar la operación OR entre ebx y eax
convertMov:
    cmp edx, 0
    je convertMovExit
convertMov1:
    mov [edi+ecx],ebx
    inc ecx
    xor ebx, ebx
    xor edx, edx
    cmp edx, 0
    je convertMovExit2
convertMovExit:
    inc edx 
convertMovExit2: 
    inc esi  ; Avanzar al siguiente carácter
    cmp BYTE PTR [esi], 0  ; Comprobar si se alcanzó el final de la cadena
    jne convertLoop1  ; Si no se alcanzó, continuar con el siguiente carácter
convertEnd:    
    pop esi
    pop edi
    ret
;--------------------------RUTINA DE XOR------------------------------------------------
decrypt:
    push esi
    push edi
    xor ecx, ecx 
    xor ebx, ebx
    xor edx, edx  
    xor eax, eax
    ; Desencriptar el texto cifrado
decrypt_loop:
    mov dl, [edi+ecx+1] ; buffer
    mov bl, [esi+ecx] ; key key
    xor dl,bl         
    mov al, [edi+ecx] 
    cmp al, dl     
    jb   jumpersub
    add dl, 000000FFh 
jumpersub:
    sub dl, al
    mov plain[ecx], dl             ;Almacenar el resultado
    inc ecx                        ;Incrementar el contador
    cmp ecx, lenc                   ;Comprobar si se alcanzó la longitud máxima
    jl decrypt_loop                ;Si no se alcanzó, continuar con el siguiente carácter
    pop esi
    pop edi
    ret




main ENDP                           ; Task: Define the end of the code using the main with the ENDP directive
END 

;decoder.exe A9A923A15BF96FE4 B00X02039AVBJICXNBJOIKCVXMKOMASUJIERNJIQWNLKFMDOPVXCMUIJBNOXCKMVIOKXCJUIHNSDIUJNRHUQWEBGYTVasuydhosgkjopdf
