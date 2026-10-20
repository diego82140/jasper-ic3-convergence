"""Generated regression models; no customer design or vendor source."""
MODELS = {
'xy': '''MODULE main
VAR x : boolean; y : boolean;
ASSIGN init(x) := FALSE; init(y) := FALSE;
next(x) := y; next(y) := FALSE;
SPEC AG !x
''',
'and_predecessor': '''MODULE main
VAR x : boolean; y : boolean; z : boolean;
ASSIGN init(x) := FALSE; init(y) := FALSE; init(z) := TRUE;
next(x) := y & z; next(y) := FALSE; next(z) := !z;
SPEC AG !x
''',
'composite_property': '''MODULE main
VAR x : boolean; y : boolean; z : boolean;
ASSIGN init(x) := FALSE; init(y) := FALSE; init(z) := FALSE;
next(x) := y; next(y) := FALSE; next(z) := z;
SPEC AG !(x & !z)
''',
'delayed_bug': '''MODULE main
VAR x : boolean; y : boolean; z : boolean;
ASSIGN init(x) := FALSE; init(y) := FALSE; init(z) := FALSE;
next(x) := y; next(y) := z; next(z) := !z;
SPEC AG !x
'''
}
