#ifndef InjectionDll_H_
#define InjectionDll_H_
#if (defined WIN32 || defined _WIN32 || defined WINCE) && defined InjectionDLL_EXPORTS  
#define InjectionDLL __declspec(dllexport) 
#else
#define InjectionDLL
#endif // InjectionDLL
InjectionDLL void __stdcall Connect();
#endif // !InjectionDll_H_

