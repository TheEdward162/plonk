; R0 = GATES to enable
CONFIG_CLOCK PROC
; Registers

	MOV R7, #0x1
	LDR R6, =RCC_CR
	LDR R5, =RCC_CFGR

; reset clock bits 16 and 18 (HESON and HSEBYP)
	LDR R1, [R6]
	BIC R1, R1, #0x50000
	STR R1, [R6]

; enable HSEON
	LDR R1, =HSEON
	STR R7, [R1]

; Wait until HSERDY is stable
	LDR R1, =HSERDY
HSE_NOT_READY
	LDR R2, [R1]
	CMP R2, #0x0
	BEQ HSE_NOT_READY

; set SCLK
	LDR R1, [R5]
	BIC R1, R1, #0xF0
	STR R1, [R5]

; set HCLK PPRE2
	LDR R1, [R5]
	BIC R1, R1, #0x3800
	STR R1, [R5]

; set HCLK PPRE1
	LDR R1, [R5]
	BIC R1, R1, #0x700
	ORR R1, R1, #0x400
	STR R1, [R5]

; set PLLSRC and PLLMUL to x3 (as 24MHz clock)
	LDR R1, [R5]
	BIC R1, R1, #0x3F0000
	ORR R1, R1, #0x50000
	STR R1, [R5]
				
; Enable PLLON
	LDR R1, =PLLON
	STR R7, [R1]

; Wait until PLLRDY is stable
	LDR R1, =PLLRDY
PLL_NOT_READY
	LDR R2, [R1]
	CMP R2, #0x0
	BEQ PLL_NOT_READY

; set PLL as clock
	LDR R1, [R5]
	BIC R1, R1, #0x3
	ORR R1, R1, #0x2
	STR R1, [R5]

; Link clock to gates
	LDR R1, =RCC_APB2ENR
	LDR R2, [R1]
	ORR R2, R2, R0
	STR R2, [R1]

	BX LR
	ENDP

; R0 = GPIO register to configure
; R1 = mask to zero
; R2 = bits to set
CONFIG_GPIO PROC

	LDR R3, [R0]
	BIC R3, R3, R1
	ORR R3, R3, R2
	STR R3, [R0]

	BX LR
	ENDP

; R0 = number of outer iterations
; The clock is set to 24MHz - 24000000 operations per second
; Delay waits for 1 ms * R0
DELAY PROC

	PUSH { R1 }

; inner should take 1 ms, that is 24000 cycles as 24MHz
; 11998 * 2 from INNER + 4 from OUTER = 24000
; Of course that doesn't work
OUTER
	NOP
	; 2998 works in the simulator
	; 9000 works on the board
	MOV R1, #9000
INNER
	SUBS R1, R1, #1
	BNE INNER

; sub the user argument
	SUBS R0, R0, #1
	BNE OUTER
	
	POP { R1 }

	BX LR
	ENDP
