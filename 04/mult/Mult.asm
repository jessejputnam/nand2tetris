// ------- SYNTAX -------
// D = data register
// A = address / data register
// M = currently selected memory register, i.e. M = RAM[A]

// ----- REGISTERS AND NUMBERS -------
// @10 = sets A to 10
// When using @ for register, use R, i.e. R5
// When using it as a number, just use the number

// ----- LABELS ------
// Label code to jump to with (LABEL)
// Use CAPS
// i.e:
// @POSITIVE
// D;JGT
// (POSITIVE)

// ----- VARIABLES ------
// Variables declared with @, 
// use lower case
// i.e. @var declares a variable named 'var'

// Iteration
// Example:


// ########################################################################

// Multiplies R0 with R1, stores result in R2

// Set product to 0
@0
D=A
@product
M=D 

// Set base and counter
@R0 
D=M 
@base
M=D
@R1
D=M 
@count 
M=D

(LOOP) 
    @count 
    D=M 
    @STORE 
    D;JEQ

    @base 
    D=M 
    @product 
    M=M+D 
    @count 
    M=M-1
    @LOOP 
    0;JMP

(STORE)
    @product 
    D=M 
    @R2 
    M=D

(END)
    @END
    0;JMP
