## Reverse Engineering resources  
[![Awesome](https://2.bp.blogspot.com/-nz0jFFFA4Hc/WHubiaz8ecI/AAAAAAAAB08/g2erX6roVBYCfwWjIGUOBYMkcB7ghRL2wCLcB/s1600/reverse%2Bengineering.png)](http://kalitut.com)
A curated list of awesome reversing resources   

- [Awesome Reversing](#awesome-reversing)
    - [Books](#books)
    - [Courses](#courses)
    - [Practice](#practice)
    - [Hex Editors](#hex-editors)
    - [Binary Format](#binary-format)
    - [Disassemblers](#disassemblers)
    - [Binary Analysis](#binary-analysis)
    - [Bytecode Analysis](#bytecode-analysis)
    - [Import Reconstruction](#import-reconstruction)
    - [Dynamic Analysis](#dynamic-analysis)
    - [Debugging](#debugging)
    - [Mac Decrypt](#mac-decrypt)
    - [Document Analysis](#document-analysis)
    - [Scripting](#scripting)
    - [Android](#android)
    - [Yara](#yara)

- - -

## Books

*Reverse Engineering Books*

* [The IDA Pro Book](http://amzn.to/2jTicOg)
* [Radare2 Book](https://www.gitbook.com/book/radare/radare2book/details)
* [Reverse Engineering for Beginners](http://beginners.re/)
* [The Art of Assembly Language](http://amzn.to/2jlxTNp)
* [Practical Reverse Engineering](http://amzn.to/2iusXRW)
* [Reversing: Secrets of Reverse Engineering](http://amzn.to/2jlnBwX)
* [Practical Malware Analysis](http://amzn.to/2jljYqE)
* [Malware Analyst's Cookbook](http://amzn.to/2iWPJDd)
* [Gray Hat Hacking](http://amzn.to/2jllIAi)
* [Access Denied](https://github.com/shaykhsiddique/academic-/blob/master/CSE107/Access%20Denied.pdf)
* [The Art of Memory Forensics](http://amzn.to/2jMJQs0)
* [Hacking: The Art of Exploitation](http://amzn.to/2jnkV19)
* [Fuzzing for Software Security](http://amzn.to/2jMKCWc)
* [Art of Software Security Assessment](http://amzn.to/2jlvtyt)
* [The Antivirus Hacker's Handbook](http://amzn.to/2jn9G99)
* [The Rootkit Arsenal](http://amzn.to/2jlgioK)
* [Windows Internals Part 1](http://amzn.to/2jlo9mA) [Part 2](http://amzn.to/2jMLCth)
* [Inside Windows Debugging](http://amzn.to/2iqFTxf)
* [iOS Reverse Engineering](https://github.com/iosre/iOSAppReverseEngineering)

## Courses

*Reverse Engineering Courses*

* [Lenas Reversing for Newbies](https://tuts4you.com/download.php?list.17)
* [Open Security Training](http://opensecuritytraining.info/Training.html)
* [Dr. Fu's Malware Analysis](http://fumalwareanalysis.blogspot.sg/p/malware-analysis-tutorials-reverse.html)
* [Binary Auditing Course](http://www.binary-auditing.com/)
* [TiGa's Video Tutorials](http://www.woodmann.com/TiGa/)
* [Legend of Random](https://tuts4you.com/download.php?list.97)
* [Modern Binary Exploitation](http://security.cs.rpi.edu/courses/binexp-spring2015/)
* [RPISEC Malware Course](https://github.com/RPISEC/Malware)
* [SANS FOR 610 GREM](https://www.sans.org/course/reverse-engineering-malware-malware-analysis-tools-techniques/Type/asc/all)
* [REcon Training](https://recon.cx/2015/training.html)
* [Blackhat Training](https://www.blackhat.com/us-16/training/)
* [Offensive Security](https://www.offensive-security.com/information-security-training/)
* [Corelan Training](https://www.corelan.be/index.php/articles/#cat_exploit-writing-tutorials)
* [Offensive and Defensive Android Reversing](https://github.com/rednaga/training/raw/master/DEFCON23/O%26D%20-%20Android%20Reverse%20Engineering.pdf)

## Practice

*Practice Reverse Engineering.  Be careful with malware.*

* [Crackmes.de](http://www.crackmes.de/)
* [OSX Crackmes](https://reverse.put.as/crackmes/)
* [ESET Challenges](http://www.joineset.com/jobs-analyst.html)
* [Flare-on Challenges](http://flare-on.com/)
* [Github CTF Archives](http://github.com/ctfs/)
* [Reverse Engineering Challenges](http://challenges.re/)
* [xorpd Advanced Assembly Exercises](http://www.xorpd.net/pages/xchg_rax/snip_00.html)
* [Virusshare.com](http://virusshare.com/)
* [Contagio](http://contagiodump.blogspot.com/)
* [Malware-Traffic-Analysis](https://malware-traffic-analysis.com/)
* [Malshare](http://malshare.com/)
* [Malware Blacklist](http://www.malwareblacklist.com/showMDL.php)
* [malwr.com](https://malwr.com/)
* [vxvault](http://vxvault.net/)

## Hex Editors

*Hex Editors*

* [HxD](https://mh-nexus.de/en/hxd/)
* [010 Editor](http://www.sweetscape.com/010editor/)
* [Hex Workshop](http://www.hexworkshop.com/)
* [HexFiend](http://ridiculousfish.com/hexfiend/)
* [Hiew](http://www.hiew.ru/)
* [hecate](https://github.com/evanmiller/hecate)

## Binary Format

*Binary Format Tools*

* [CFF Explorer](http://www.ntcore.com/exsuite.php)
* [Cerbero Profiler](http://cerbero.io/profiler/) // [Lite PE Insider](http://cerbero.io/peinsider/)
* [Detect It Easy](http://ntinfo.biz/)
* [PeStudio](http://www.winitor.com/)
* [PEiD](https://tuts4you.com/download.php?view.398)
* [MachoView](https://github.com/gdbinit/MachOView)
* [nm](https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man1/nm.1.html) - View Symbols
* [file](https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man1/file.1.html) - File information
* [codesign](https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man1/codesign.1.html) - Code signing information usage: codesign -dvvv filename

## Disassemblers

*Disassemblers*

* [IDA Pro](https://www.hex-rays.com/products/ida/index.shtml)
* [GHIDRA](https://ghidra-sre.org/)
* [Binary Ninja](https://binary.ninja/)
* [Radare](http://www.radare.org/r/)
* [Hopper](http://hopperapp.com/)
* [Capstone](http://www.capstone-engine.org/)
* [objdump](http://linux.die.net/man/1/objdump)
* [fREedom](https://github.com/cseagle/fREedom)

## Binary Analysis

*Binary Analysis Resources*

* [Mobius Resources](http://www.msreverseengineering.com/research/)
* [z3](https://z3.codeplex.com/)
* [bap](https://github.com/BinaryAnalysisPlatform/bap)
* [angr](https://github.com/angr/angr)

## Bytecode Analysis

*Bytecode Analysis Tools*

* [dnSpy](https://github.com/0xd4d/dnSpy)
* [Bytecode Viewer](https://bytecodeviewer.com/)
* [Bytecode Visualizer](http://www.drgarbage.com/bytecode-visualizer/)
* [JPEXS Flash Decompiler](https://www.free-decompiler.com/flash/)

## Import Reconstruction

*Import Reconstruction Tools*

* [ImpRec](http://www.woodmann.com/collaborative/tools/index.php/ImpREC)
* [Scylla](https://github.com/NtQuery/Scylla)
* [LordPE](http://www.woodmann.com/collaborative/tools/images/Bin_LordPE_2010-6-29_3.9_LordPE_1.41_Deluxe_b.zip)

## Dynamic Analysis

*Dynamic Analysis Tools*

* [ProcessHacker](http://processhacker.sourceforge.net/)
* [Process Explorer](https://technet.microsoft.com/en-us/sysinternals/processexplorer)
* [Process Monitor](https://technet.microsoft.com/en-us/sysinternals/processmonitor)
* [Autoruns](https://technet.microsoft.com/en-us/sysinternals/bb963902)
* [Noriben](https://github.com/Rurik/Noriben)
* [API Monitor](http://www.rohitab.com/apimonitor)
* [iNetSim](http://www.inetsim.org/)
* [SmartSniff](http://www.nirsoft.net/utils/smsniff.html)
* [TCPView](https://docs.microsoft.com/en-us/sysinternals/downloads/tcpview)
* [Wireshark](https://www.wireshark.org/download.html)
* [Fakenet](http://practicalmalwareanalysis.com/fakenet/)
* [Volatility](https://github.com/volatilityfoundation/volatility)
* [Dumpit](http://www.moonsols.com/products/)
* [LiME](https://github.com/504ensicsLabs/LiME)
* [Cuckoo](https://www.cuckoosandbox.org/)
* [Objective-See Utilities](https://objective-see.com/products.html)
* [XCode Instruments](https://developer.apple.com/xcode/download/) - XCode Instruments for Monitoring Files and Processes [User Guide](https://developer.apple.com/library/watchos/documentation/DeveloperTools/Conceptual/InstrumentsUserGuide/index.html)
* [dtrace](http://dtrace.org/blogs/brendan/2011/10/10/top-10-dtrace-scripts-for-mac-os-x/) - sudo dtruss = strace [dtrace recipes](http://mfukar.github.io/2014/03/19/dtrace.html)
* [fs_usage](https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man1/fs_usage.1.html) - report system calls and page faults related to filesystem activity in real-time.  File I/O: fs_usage -w -f filesystem
* [dmesg](https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man8/dmesg.8.html) - display the system message buffer

## Debugging

*Debugging Tools*

* [WinDbg](https://msdn.microsoft.com/en-us/windows/hardware/hh852365.aspx)
* [OllyDbg v1.10](http://www.ollydbg.de/)
* [OllyDbg v2.01](http://www.ollydbg.de/version2.html)
* [OllySnD](https://tuts4you.com/download.php?view.2061)
* [Olly Shadow](https://tuts4you.com/download.php?view.6)
* [Olly CiMs](https://tuts4you.com/download.php?view.1206)
* [Olly UST_2bg](https://tuts4you.com/download.php?view.1206)
* [x64dbg](http://x64dbg.com/#start)
* [gdb](https://www.gnu.org/software/gdb/)
* [vdb](https://github.com/vivisect/vivisect)
* [lldb](http://lldb.llvm.org/)
* [qira](http://qira.me/)
* [unicorn](https://github.com/unicorn-engine/unicorn)

## Mac Decrypt

*Mac Decrypting Tools*

* [Cerbero Profiler](http://cerbero-blog.com/?p=1311) - Select all -> Copy to new file
* [AppEncryptor](https://github.com/AlanQuatermain/appencryptor) - Tool for decrypting
* [Class-Dump](http://stevenygard.com/projects/class-dump/) - use deprotect option
* [readmem](https://github.com/gdbinit/readmem) - OS X Reverser's process dumping tool

## Document Analysis

*Document Analysis Tools*

* [Ole Tools](http://www.decalage.info/python/oletools)
* [Didier's PDF Tools](http://blog.didierstevens.com/programs/pdf-tools/)
* [Origami](https://github.com/cogent/origami-pdf)

## Scripting

*Scripting*

* [IDA Python Src](https://github.com/idapython/src)
* [IDC Functions Doc](https://www.hex-rays.com/products/ida/support/idadoc/162.shtml)
* [Using IDAPython to Make your Life Easier](http://researchcenter.paloaltonetworks.com/tag/idapython/)
* [Introduction to IDA Python](https://tuts4you.com/download.php?view.3229)
* [The Beginner's Guide to IDA Python](https://leanpub.com/IDAPython-Book)
* [IDA Plugin Contest](https://www.hex-rays.com/contests/)
* [onehawt IDA Plugin List](https://github.com/onethawt/idaplugins-list)
* [pefile Python Library](https://github.com/erocarrera/pefile)

## Android

*Android tools*

* [Android Studio](http://developer.android.com/sdk/index.html)
* [APKtool](http://ibotpeaches.github.io/Apktool/)
* [dex2jar](https://github.com/pxb1988/dex2jar)
* [Bytecode Viewer](https://bytecodeviewer.com/)
* [IDA Pro](https://www.hex-rays.com/products/ida/index.shtml)
* [JaDx](https://github.com/skylot/jadx)

## Yara

*Yara Resources*

* [Yara docs](http://yara.readthedocs.org/en/v3.4.0/writingrules.html)
* [Cheatsheet](https://gist.github.com/0xtyh/eeabc765e9befad9b80a)
* [yarGen](https://github.com/Neo23x0/yarGen)
* [Yara First Presentation](https://www.first.org/resources/papers/conference2014/first_2014_-_schuster-_andreas_-_yara_basic_and_advanced_20140619.pdf)

Please have a look at
* [Top Hacking Books](http://www.kalitut.com/2016/12/best-ethical-hacking-books.html)
* [Top Reverse Engineering Books](http://www.kalitut.com/2017/01/Best-reverse-engineering-books.html)
* [Top Machine learning Books](http://www.kalitut.com/2017/01/machine-learning-book.html)
* [Top 5 books Programming Books](http://www.kalitut.com/2017/01/Top-Programming-Books.html)
* [Top Java Books](http://www.kalitut.com/2017/01/Best-Java-Programming-Books.html)

