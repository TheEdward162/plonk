; R0 = GATES to enable
CONFIG_CLOCK PROC
; Registers

	MOV R7, #0x1
	LDR R6, =RCC_CR
	LDR R5, =RCC_CFGR

; reset clock bits 16 and 18 (HESON and HSEBYP)
	LDR R4, [R6]
	BIC R4, R4, #0x50000
	STR R4, [R6]

; enable HSEON
	LDR R4, =HSEON
	STR R7, [R4]

; Wait until HSERDY is stable
	LDR R4, =HSERDY

HSE_NOT_READY
	LDR R3, [R4]
	TST R3, #1
	BEQ HSE_NOT_READY

; set SCLK
	LDR R4, [R5]
	BIC R4, R4, #0xF0
	STR R4, [R5]

; set HCLK PPRE2
	LDR R4, [R5]
	BIC R4, R4, #0x3800
	STR R4, [R5]

; set HCLK PPRE1
	LDR R4, [R5]
	BIC R4, R4, #0x700
	ORR R4, R4, #0x200
	STR R4, [R5]

; set PLL as 24MHz clock
	LDR R4, [R5]
	BIC R4, R4, #0x3F0000
	ORR R4, R4, #0x50000
	STR R4, [R5]
				
; Enable PLLON
	LDR R4, =PLLON
	STR R7, [R4]

; Wait until PLLRDY is stable
	LDR R4, =PLLRDY

PLL_NOT_READY
	LDR R3, [R4]
	TST R3, #1
	BEQ PLL_NOT_READY

; set PLL as clock
	LDR R4, [R5]
	BIC R4, R4, #0x3
	ORR R4, R4, #0x2
	STR R4, [R5]

; Link clock to gates
	LDR R4, =RCC_APB2ENR
	LDR R3, [R4]
	ORR R3, R3, R0
	STR R3, [R4]

	BX LR
	ENDP

; R0 = GPIO register to configure
; R1 = mask to zero
; R2 = bits to set
CONFIG_GPIO PROC

	LDR R7, [R0]
	BIC R7, R7, R1
	ORR R7, R7, R2
	STR R7, [R0]

	BX LR
	ENDP

; R0 = number of outer iterations
DELAY PROC

OUTER
	MOV R7, #40000
INNER
	SUBS R7, R7, #1
	BNE INNER

; sub the user argument
	SUBS R0, R0, #1
	BNE OUTER

	BX LR
	ENDP
