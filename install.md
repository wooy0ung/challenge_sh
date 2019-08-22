环境搭建

IDA Pro
pwntool
peda
ropper

在kali linux下执行
```
sudo dpkg --add-architecture i386 && apt-get update

apt-get install -y git nasm  python build-essential python-dev python-pip python-setuptools libc6-dbg libc6-dbg:i386 gcc-multilib gdb-multiarch gcc wget curl glibc-source cmake python-capstone socat netcat ruby

pip install --no-cache-dir pwntools ropper

gem install one_gadget

cd ~/ && git clone https://github.com/longld/peda.git && echo "source ~/peda/peda.py" >> ~/.gdbinit

cd ~/ && git clone https://github.com/scwuaptx/Pwngdb.git && cp ~/Pwngdb/.gdbinit ~/
```

远程地址

level0
nc pwn2.jarvisoj.com 9881

level1
nc pwn2.jarvisoj.com 9877

level2
nc pwn2.jarvisoj.com 9878

level3
nc pwn2.jarvisoj.com 9879

level2_x64
nc pwn2.jarvisoj.com 9882

level3_x64
nc pwn2.jarvisoj.com 9883

level4
nc pwn.jarvisoj.com 9876

level5
nc pwn.jarvisoj.com 9877


逆向环境

IDA Pro(含python2.7)插件

1、 安装yara-python，最简单的方式是使用：pip install yara-python

yara-python地址：https://github.com/VirusTotal/yara-python

2、 下载findcrypt.py复制到插件目录
https://github.com/polymorf/findcrypt-yara

IDA 7.0\plugins\findcrypt3.rules

IDA 7.0\plugins\findcrypt3.py


Ollydbg

吾爱破解OD


安卓

JEB
apktoolbox
网易mumu模拟器


mips arm or 其他架构

ghidra(需要java 11环境)


angr安装
https://bbs.pediy.com/thread-248914.htm