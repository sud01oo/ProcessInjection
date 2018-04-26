# **ProcessInjection**

# 一些进程注入方法的实现及分析，分析在：[看雪论坛](https://bbs.pediy.com/user-703263.htm)


## **已完成**：

1. **Classic Injection**
	* CommonInjection
	* InjectionDLL
	* DLLTest
2. **Shellcode Injection**
	* ShellcodeInjdection
	> x64，shellcode使用msf生成。
3. **Reflection Injection**
  	* ReflectiveDLLInjection
	* ReflectiveDLL
	* ReflectiveDLLPEForm
	>代码参考：https://github.com/stephenfewer/ReflectiveDLLInjection<br/>
	>为方便调试，该工程是在外部实现的对DLL的解析，其实已经与下一个项目相同。
	

4. **MEMORY MODULE**
	
  	* Memory Module
	* MemroyInjectionDLL
	>使用了Reflection Injection的代码，对部分代码进行了修改。<br/>
	>参考：https://github.com/fancycode/MemoryModule	
	

5. **Process Hollowing(冷注入)**
	
  	* EXEPayload
	* HollowingDropper
	>参考：https://github.com/m0n0ph1/Process-Hollowing <br/>
	在原项目的基础上，重写了项目，支持x86和x64
	"热"注入失败，以后再尝试。给出文章链接：
	
6. **Gargoyle(石像鬼)**
	* Gargoyle
	>参考：https://jlospinoso.github.io/security/assembly/c/cpp/developing/software/2017/03/04/gargoyle-memory-analysis-evasion.html <br/>
	>简介：该项目是一种对内存扫描逃避技术的PoC。只支持x86，x64下没有尝试更改。


## **进行中**:<br/>

+ Process Hollowing(热注入)
	>http://riscy.business/2017/11/bypassing-modern-process-hollowing-detection/
	
>***“images”文件夹是在学习过程中，会遇到的一些数据结构的可视化图片，方便查阅相关结构。***
