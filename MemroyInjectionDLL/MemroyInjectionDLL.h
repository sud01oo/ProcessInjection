// The following ifdef block is the standard way of creating macros which make exporting 
// from a DLL simpler. All files within this DLL are compiled with the MEMROYINJECTIONDLL_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see 
// MEMROYINJECTIONDLL_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef MEMROYINJECTIONDLL_EXPORTS
#define MEMROYINJECTIONDLL_API __declspec(dllexport)
#else
#define MEMROYINJECTIONDLL_API __declspec(dllimport)
#endif

// This class is exported from the MemroyInjectionDLL.dll
class MEMROYINJECTIONDLL_API CMemroyInjectionDLL {
public:
	CMemroyInjectionDLL(void);
	// TODO: add your methods here.
};

extern MEMROYINJECTIONDLL_API int nMemroyInjectionDLL;

MEMROYINJECTIONDLL_API int fnMemroyInjectionDLL(void);
