# FloatZone


**FloatZone**: a compiler-based sanitizer to detect spatial and temporal memory errors in C/C++ programs
using lightweight checks that leverage the Floating Point Unit (FPU).

**Paper:** [https://www.vusec.net/projects/floatzone/](https://www.vusec.net/projects/floatzone/)

## Dependencies

(Tested on system running Ubuntu 22.04, glibc 2.35, and a stock v5.15 Linux kernel)

```
sudo apt install ninja-build cmake gcc-9 autoconf2.69 bison build-essential flex texinfo libtool zlib1g-dev
pip3 install psutil terminaltables
```

## How to install


```
git clone https://github.com/vusec/floatzone.git --recurse-submodules
```

Edit `env.sh` and update `FLOATZONE_TOP` with the full path where you cloned this repository.

(OPTIONAL) To run SPEC benchmarks, update also the variable `FLOATZONE_SPEC06` and `FLOATZONE_SPEC17` with the full path of your SPEC instllation.

Then, load the environment in your current shell:
```
source env.sh
```

**IMPORTANT**: always ensure to load `env.sh` in your terminal before doing any of the following steps

Finally, let's install everything. This will take a while since LLVM is quite a big project:

```
./install.sh
```


