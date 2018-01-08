#ifndef InjectionDll_H_
#define InjectionDll_H_
#ifdef InjectionDLL
#define InjectionDLL extern "C" _declspec(dllimport)
#else
#define InjectionDLL extern "C" _declspec(dllexport)
#endif // InjectionDLL
InjectionDLL void Ping();
#endif // !InjectionDll_H_

