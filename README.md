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
	<li>参考</li>
	<li>https://github.com/fancycode/MemoryModule</li>	
	</ul>
</ol>
<ol>4：Process Hollowing
	<ul>
  	<li>EXEPayload</li>
	<li>HollowingDropper</li>
	</ul>
</ol>

<h2>进行中:</h2>
Process Hollowing
	<ul>
  	<li>将会使用“热”Hollowing，“冷”Hollowing两种方式进行注入</li>
	</ul>
“images”文件夹是在学习过程中，会遇到的一些数据结构的可视化图片，方便查阅相关结构。
