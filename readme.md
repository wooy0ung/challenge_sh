环境搭建

IDA Pro
pwntool
peda
ropper

在kali linux下执行
```
sudo dpkg --add-architecture i386 && apt-get update && \

apt-get install -y \
   git nasm  python \
   build-essential \
   python-dev python-pip python-setuptools \
   libc6-dbg \
   libc6-dbg:i386 \
   gcc-multilib \
   gdb-multiarch \
   gcc \
   wget \
   curl \
   glibc-source \
   cmake \
   python-capstone \
   socat \
   netcat \
   ruby

pip install --no-cache-dir pwntools ropper ancypatch swpwn

gem install one_gadget

sudo cd ~/ && \
    git clone https://github.com/longld/peda.git && \
    echo "source ~/peda/peda.py" >> ~/.gdbinit

sudo cd ~/ && \
    git clone https://github.com/scwuaptx/Pwngdb.git && \
    cp ~/Pwngdb/.gdbinit ~/
```