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

@product
M=0             // set product to 0
@R1
D=M
@i 
M=D             // set i to multiplier
@R0
D=M
@base           // set base number
M=D

(LOOP)
    @i
    D=M
    @STOP
    D;JEQ       // if i == 0 goto STOP


    @base 
    D=M
    @product
    M=M+D       // add base to product
    @i 
    M=M-1       // decrement i
    @LOOP
    0;JMP       // return to LOOP


(STOP)
    @product
    D=M 
    @R2 
    M=D         // RAM[2] = product

(END)
    @END
    0;JMP