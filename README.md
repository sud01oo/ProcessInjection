# ProcessInjection

一些进程注入方法的实现及分析，分析在：bbs.pediy.com
------------------------------------------------

已完成：
---------
<ol>1：Classic Injection
	<ul>
  	<li>CommonInjection</li>
  	<li>InjectionDLL</li>
		<li>DLLTest</li>
		</ul>
</ol>
<ol>2：Reflection Injection
	<ul>
  	<li>ReflectiveDLLInjection</li>
	<li>ReflectiveDLL</li>
	<li>ReflectiveDLLPEForm</li>
		<li>*代码参考：https://github.com/stephenfewer/ReflectiveDLLInjection<br/></li>
		<li>*为方便调试，该工程是在外部实现的对DLL的解析，其实已经与下一个项目相同。<br/></li>
	</ul>
</ol>
<ol>3：MEMORY MODULE
	<ul>
  	<li>Memory Module</li>
	<li>MemroyInjectionDLL</li>
	<li>使用了Reflection Injection的代码，对部分代码进行了修改。</li>
	<li>参考：https://github.com/fancycode/MemoryModule</li>	
	</ul>
</ol>
<ol>4：Process Hollowing
	<ul>
  	<li>EXEPayload</li>
	<li>HollowingDropper（冷注入）</li>
	<li>参考：https://github.com/m0n0ph1/Process-Hollowing 在原项目的基础上，重写了项目，支持x86和x64</li>
	<li>在原项目的基础上，重写了项目，支持x86和x64</li>
	<li>"热"注入失败，源码无法编译，缺少资源文件，项目使用vs online导致一堆问题。给出文章链接：</li>
		<li>http://riscy.business/2017/11/bypassing-modern-process-hollowing-detection/</li>
	</ul>
</ol>

<h2>进行中:</h2>
石像鬼
	<ul>
  	<li>https://jlospinoso.github.io/security/assembly/c/cpp/developing/software/2017/03/04/gargoyle-memory-analysis-evasion.html</li>
	</ul>
“images”文件夹是在学习过程中，会遇到的一些数据结构的可视化图片，方便查阅相关结构。
