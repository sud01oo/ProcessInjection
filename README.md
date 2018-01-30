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
  	<li>对于这种注入，我在Github上找到了两个项目，以供参考，由于和Reflection注入目标相同，稍后会上传二者之间不同部分的代码。</li>
	<li>项目地址</li>
	<li>https://github.com/DarthTon/Blackbone</li>
	<li>https://github.com/fancycode/MemoryModule</li>	
	</ul>
</ol>

<h2>进行中:</h2>
MEMORY MODULE
	<ul>
  	<li>尝试将反射注入的可执行项目更改为内存模块，内存模块项目的最终目的就是将一个在内存中的DLL加载起来，这种加载不同于反射式注入的地方在于，反射式注入存在大块RWX内存区域，而内存模块将会尽可能的将内存属性变得更逼真</li>
	</ul>
“images”文件夹是在学习过程中，会遇到的一些数据结构的可视化图片，方便查阅相关结构。
