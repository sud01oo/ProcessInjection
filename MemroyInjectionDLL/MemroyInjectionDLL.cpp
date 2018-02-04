// MemroyInjectionDLL.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "MemroyInjectionDLL.h"


// This is an example of an exported variable
MEMROYINJECTIONDLL_API int nMemroyInjectionDLL=0;

// This is an example of an exported function.
MEMROYINJECTIONDLL_API int fnMemroyInjectionDLL(void)
{
    return 42;
}

// This is the constructor of a class that has been exported.
// see MemroyInjectionDLL.h for the class definition
CMemroyInjectionDLL::CMemroyInjectionDLL()
{
    return;
}
