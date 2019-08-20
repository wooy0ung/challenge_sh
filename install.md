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