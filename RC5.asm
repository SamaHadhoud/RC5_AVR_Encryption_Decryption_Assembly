
; RC5_ALGORITHM:

; Set Stack Pointer to top of RAM
ldi r20, high(RAMEND)
out SPH,r20
ldi r20, low(RAMEND)
out SPL,r20

;Define Variables:
.EQU R = 8    ; no. of rounds
.EQU T = 18   ; size of the expanded key table
.EQU W = 16   ; word size in bits
.EQU U = 2    ; word size in bytes
.EQU B = 12   ; no. of bytes in the secret key
.EQU C = 6    ; no. of words in the secret key
.EQU N = 54   ; no. of iterations of the key expansion module
; the constant P used in the key expansion module
.EQU PL = 0xe1 
.EQU PH = 0xb7
; the constant Q used in the key expansion module
.EQU QL = 0x37
.EQU QH = 0x9e

;User Input Data:
.MACRO INPUT
	.DEF AH = R17
	ldi AH, @0

	.DEF AL = R16
	ldi AL, @1

	.DEF BH = R19
	ldi BH, @2

	.DEF BL = R18
	ldi BL, @3 

.ENDMACRO

;Define Secret Key:
.MACRO SECRET_KEY
	.EQU BY0 = 0x0200
	.EQU BY1 = 0x0201
	.EQU BY2 = 0x0202
	.EQU BY3 = 0x0203
	.EQU BY4 = 0x0204
	.EQU BY5 = 0x0205
	.EQU BY6 = 0x0206
	.EQU BY7 = 0x0207
	.EQU BY8 = 0x0208
	.EQU BY9 = 0x0209
	.EQU BY10 = 0x020A
	.EQU BY11 = 0x020B
		LDI R20, @11
		STS BY0, R20
		LDI R20, @10
		STS BY1, R20
		LDI R20, @9
		STS BY2, R20
		LDI R20, @8
		STS BY3, R20
		LDI R20, @7
		STS BY4, R20
		LDI R20, @6
		STS BY5, R20
		LDI R20, @5
		STS BY6, R20
		LDI R20, @4
		STS BY7, R20
		LDI R20, @3
		STS BY8, R20
		LDI R20, @2
		STS BY9, R20
		LDI R20, @1
		STS BY10, R20
		LDI R20, @0
		STS BY11, R20
.ENDMACRO

;Define needed operations
.MACRO XOR_WORD            
		EOR @1, @3
		EOR @0, @2
.ENDMACRO

.MACRO ADD_WORD            
		ADD @1, @3
		ADC @0, @2
.ENDMACRO

.MACRO SUB_WORD             
		SUB @1, @3
		SBC @0, @2
.ENDMACRO

.MACRO ROTL_WORD
		TST @2
		BREQ ZEROL
		MOV R25, @2         
	ROTL:
		ROL @1
		BST @0, 7
		ROL @0
		BLD @1, 0
		DEC R25
		BRNE ROTL
	ZEROL:
		nop
.ENDMACRO


.MACRO ROTR_WORD
		TST @2
		BREQ ZEROR
		MOV R25, @2          
	ROTR:
		ROR @0
		BST @1, 0
		ROR @1
		BLD @0, 7
		DEC R25
		BRNE ROTR
	ZEROR:
		nop
.ENDMACRO

;**********************************RC5_SETUP***********************************
.MACRO RC5_SETUP
		;First step: {
		; renaming step.
		.EQU LW0L = BY0            ;Position 0x0100
		.EQU LW0H = BY1            ;Position 0x0101
		;}

		;Second step: {
		.EQU S0L = 0x0210
		.EQU S0H = 0x0211
		.EQU S1L = 0x0212
		.EQU S1H = 0x0213

		;Adjust Z pointer to point to S[0]
		LDI ZL, low(S0L)
		LDI ZH, high(S0L)

		;Initializing S[0], S[0] = Pw
		LDI R21, PL
		LDI R22, PH
		STS S0L, R21
		STS S0H, R22

		;Qw in Registers  r22(H) r21(L) 
		LDI R21, QL
		LDI R22, QH

		;Startting the loop of second step.
		LDI R20, T ;for i = l to t – l
		subi r20, 1
	LOOP:
		LD R23,	Z+  ;S[i-1]
		LD R24, Z+

		ADD_WORD R24, R23, R22, R21 ;S[i] = S[i – 1] + Qw

		ST Z, R23       ;store in s[i]
		STD Z+1, R24

		DEC R20
		BRNE LOOP
	;}

	;Third step: {
	clr R0 ; A in R0 (L) and R1 (H)
	clr R1
	clr R2 ; B in R2 (L) and R3 (H)
	clr R3

		;Adjust Z and Y pointer
		LDI ZL, low(S0L)
		LDI ZH, high(S0L)
		LDI YL, low(LW0L)
		LDI YH, high(LW0L)

		;Constructe the body of key_expansion {
		LDI R20, N
	LOOP2:
		;Get the A value {

		ADD_WORD R1, R0, R3, R2  ;A = A + B

		LD R23, Z  ; Loading s[i]
		LDD R24, Z+1

		ADD_WORD R1, R0, R24, R23  ;A = S[i] + A

		ldi R22 , 3 ; Rotation Counter
		ROTL_WORD R1, R0, R22

		ST Z, R0  ; Storing A in S[i]
		STD Z+1, R1

		;}

		;Get the B value {

		ADD_WORD R3, R2, R1, R0 ; B = B + A

		mov R22, R2 ; Setting Rotation Counter
		andi R22,0x0F

		LD R23, Y ; Loading L[i]
		LDD R24, Y+1

		ADD_WORD R3, R2, R24, R23 ;B = L[j] + B

		ROTL_WORD R3, R2, R22

		ST Y, R2  ; Storing B in L[i]
		STD Y+1, R3

		;}
		; Checking if exceeding the S array (mod)
		call I_RESET
		; Checking if exceeding the L array (mod)
		call J_RESET

		;Loop controling
		DEC R20
		BRNE LOOP2
		;}
	;}

.ENDMACRO
;*********************************RC5_ENCRYPT**********************************

.MACRO RC5_ENCRYPT
		;Adjust X pointer
		LDI XL, 0x14           ;Position of S[2]
		LDI XH, 0x02

		;Initialling A and B
		LDS R22, S0L
		LDS R21,S0H
		ADD_WORD AH, AL, R21, R22
		LDS R22, S1L
		LDS R21,S1H
		ADD_WORD BH, BL, R21, R22

		;Startting the loop
		LDI R20, R
	LOOP3:
		;Compute A
		LDI R22, 0x0F
		AND R22, BL

		LD R23, X+
		LD R24, X+
		XOR_WORD AH, AL, BH, BL
		ROTL_WORD AH, AL, R22  
		ADD_WORD AH, AL, R24, R23

		;Compute B
		LDI R22, 0x0F
		AND R22, AL

		LD R23, X+
		LD R24, X+
		XOR_WORD BH, BL, AH, AL
		ROTL_WORD BH, BL, R22  
		ADD_WORD BH, BL, R24, R23

		;Loop controling
		DEC R20
		BRNE LOOP3

.ENDMACRO
;********************************RC5_DECRYPT***********************************

.MACRO RC5_DECRYPT
		;Adjust X pointer
		LDI XL, 0x34         ;Position of S[2*i+1], where i=8
		LDI XH, 0x02

		;Startting the loop {
		LDI R20, 8
	LOOP4:
		;Compute B {
		LDI R22, 0x0F
		AND R22, AL

		LD R23, -X             
		LD R24, -X
		SUB_WORD BH, BL, R23, R24
		ROTR_WORD BH, BL, R22
		XOR_WORD BH, BL, AH, AL
		;}

		;Compute A {
		LDI R22, 0x0F
		AND R22, BL

		LD R23, -X
		LD R24, -X
		SUB_WORD AH, AL, R23, R24
		ROTR_WORD AH, AL, R22
		XOR_WORD AH, AL, BH, BL
		;}

		
		;Loop controling
		DEC R20
		BRNE LOOP4
		;}
		LDS R22, S0H
		LDS R21, S0L
		SUB_WORD AH, AL, R22, R21
		LDS R22, S1H
		LDS R21, S1L
		SUB_WORD BH, BL, R22, R21

.ENDMACRO

;********************************TEST***********************************
start:
SECRET_KEY 00,00,00,00,00,00,00,00,00, 00,00,00
RC5_SETUP

    ; S     A      M    A
INPUT 0X53, 0X41, 0X4D, 0X41
RC5_ENCRYPT
RC5_DECRYPT

    ;  A      H    H     H
INPUT 0X41, 0X48, 0X48, 0X48
RC5_ENCRYPT
RC5_DECRYPT

    ;	B      L   A    x
INPUT 0X42, 0X4C, 0X41, 0X78
RC5_ENCRYPT
RC5_DECRYPT

NOP


I_RESET :
	inc ZL ; We increment twice as the counter counts 16 bit values (2 Locations).6
	inc ZL
	ldi R21, 0x34 ;Load last location in R20
	cpse ZL , R21 ; comparing the low bites as the higher bytes won'T 
				;change (lower bits are enough to represent the diff between the first and last locations)
	ret	
	ldi ZL , low(S0L); return to 0x0110
	ret
J_RESET:
	inc YL ; We increment twice as the counter counts 16 bit values (2 Locations)
	inc YL
	ldi R21 , 0x0C ;Load last location in R20
	cpse Yl , R21  ; comparing the low bites as the higher bytes won't- ;change (lower bits are enough to represent the diff between the first and last locations)
	ret
	LDI YL, low(LW0L) ; return to 0x0100
	ret

