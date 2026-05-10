grammar L;

program
    : chunk EOF
    ;

chunk
    : stat*
    ;

stat
    : vardecl
    | funcdecl
    | assignstat
    | ifstat
    | whilestat
    | retstat
    | funcallstat
    | blockstat
    ;

vardecl
    : primitivetype IDENTIFIER ('=' expr)? ';'
    | primitivetype IDENTIFIER '[' expr ']' ('=' expr)? ';'
    ;

funcdecl
    : (primitivetype | 'void') IDENTIFIER '(' parlist ')' blockstat
    ;

parlist
    : param (',' param)*
    |
    ;

param
    : primitivetype IDENTIFIER
    ;

assignstat
    : IDENTIFIER '=' expr ';'
    | IDENTIFIER '[' expr ']' '=' expr ';'
    ;

retstat
    : RET expr ';'
    ;

ifstat
    : IF '(' expr ')' blockstat (ELSE blockstat)?
    ;

whilestat
    : WHILE '(' expr ')' blockstat
    ;

blockstat
    : '{' chunk '}'
    ;

funcallstat
    : IDENTIFIER LPAR args RPAR ';' 
    ;

expr
    : factor
    | expr (STAR | DIV) expr
    | expr (PLUS | MINUS) expr
    | expr (SL | SR) expr
    | expr (ANDOP | OROP) expr
    | expr (GT | GE | LT | LE | EQ | NEQ) expr
    | expr (AND | OR) expr
    ;

factor
    : literal
    | MINUS expr
    | IDENTIFIER
    | IDENTIFIER '[' expr ']'
    | LPAR expr RPAR
    | funccall
    ;

literal
    : NUM_LIT
    | STR_LIT
    ;

funccall
    : IDENTIFIER LPAR args RPAR 
    ;

args
    : expr (',' expr)*
    |
    ;

primitivetype
    : INT
    | STR
    ;

/*---------------------------------Lexer--------------------------------- */
LPAR: '(';
RPAR: ')';
LB: '[';
RB: ']';
LP: '{';
RP: '}';
SEMI: ';';
COMMA: ',';
VOID: 'void';
INT: 'int';
STR: 'string';
RET: 'return';
WHILE: 'while';
IF: 'if';
ELSE: 'else';
MINUS: '-';
PLUS: '+';
STAR: '*';
DIV: '/';
SL: '<<';
SR: '>>';
ANDOP: '&';
OROP: '|';
GT: '>';
LT: '<';
GE: '>=';
LE: '<=';
EQ: '==';
NEQ: '!=';
AND: '&&';
OR: '||';
ASSIGN: '=';

fragment DIGIT
    : [0-9]
    ;

fragment HEX_DIGIT
    : [0-9a-f]
    ;

NUM_LIT
    : DIGIT+
    | '0x' HEX_DIGIT+
    ;

fragment STR_CHAR
    : ~[\r\n\\"] 
    ;

STR_LIT
    : ["] (STR_CHAR)* ["]
    ;

IDENTIFIER
    : [a-zA-Z_] [a-zA-Z0-9_]*
    ;

NL: '\n' -> skip;
WS : [ \t\f\b]+ -> skip;





