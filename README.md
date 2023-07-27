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

(OPTIONAL) To run SPEC benchmarks, update also the variable `FLOATZONE_SPEC06` with the full path of your SPEC installation.

Then, load the environment in your current shell:
```
source env.sh
```

**IMPORTANT**: always ensure to load `env.sh` in your terminal before doing any of the following steps

Finally, let's install everything. This will take a while since LLVM is quite a big project:

```
./install.sh
```

## How to test FloatZone is working

Compile the example `buggy.c` and `uaf.c`

```
cd examples
make clean
make
make uaf
```

This is the expected output:

```
./buggy_floatzone_run_base 15
A
```

```
./buggy_floatzone_run_base 16

!!!! [FLOATZONE] Fault addr = 0x7fffffffdc10 !!!!
0x7fffffffdbd0: e0 11 40 00 
0x7fffffffdbd4: 00 00 00 00 
0x7fffffffdbd8: 00 dc ff ff 
0x7fffffffdbdc: ff 7f 00 00 
0x7fffffffdbe0: 40 d0 ff f7 
0x7fffffffdbe4: ff 7f 00 00 
0x7fffffffdbe8: 2e 12 40 00 
0x7fffffffdbec: 00 00 00 00 
0x7fffffffdbf0: 89 8b 8b 8b 
0x7fffffffdbf4: 8b 8b 8b 8b 
0x7fffffffdbf8: 8b 8b 8b 8b 
0x7fffffffdbfc: 8b 8b 8b 8b 
0x7fffffffdc00: 41 41 41 41 
0x7fffffffdc04: 41 41 41 41 
0x7fffffffdc08: 41 41 41 41 
0x7fffffffdc0c: 41 41 41 41 
0x7fffffffdc10: 89 8b 8b 8b  <-----
0x7fffffffdc14: 8b 8b 8b 8b 
0x7fffffffdc18: 8b 8b 8b 8b 
0x7fffffffdc1c: 8b 8b 8b 8b 
0x7fffffffdc20: 00 00 00 00 
0x7fffffffdc24: 00 00 00 00 
0x7fffffffdc28: 00 00 00 00 
0x7fffffffdc2c: 00 00 00 00 
0x7fffffffdc30: a0 3d 40 00 
0x7fffffffdc34: 00 00 00 00 
0x7fffffffdc38: 90 7d 74 f1 
0x7fffffffdc3c: ff 7f 00 00 
0x7fffffffdc40: 00 00 00 00 
0x7fffffffdc44: 00 00 00 00 
0x7fffffffdc48: e0 11 40 00 
0x7fffffffdc4c: 00 00 00 00 

Fault RIP = 0x40123d
Backtrace:
 - [0] ./buggy_floatzone_run_base() [0x40123d]
 - [1] /lib/x86_64-linux-gnu/libc.so.6(+0x29d90) [0x7ffff1747d90]
 - [2] /lib/x86_64-linux-gnu/libc.so.6(__libc_start_main+0x80) [0x7ffff1747e40]
 - [3] /home/sec23_ae/floatzone/runtime/libwrap.so(__libc_start_main+0x1fa) [0x7ffff19502fa]
 - [4] ./buggy_floatzone_run_base() [0x401095]
```

## Benchmarks

### CPU SPEC

To run SPEC06 benchmarks simply run the following command:

```
python3 run.py run spec2006 default_O2 asan_O2 floatzone_O2 --build --parallel=proc --parallelmax=1
```

This will run baseline, ASan and FloatZone all together.

To compute the respective time and memory overhead do: (substitute `run.2023-06-20.15-37-32/` with your result folder)

```
python3 run.py report spec2006 results/run.2023-06-20.15-37-32/ --aggregate geomean --field runtime:median maxrss:median
```

This is an expected output:

```
+ spec2006 aggregated data ----------------------------------------------+
|               asan_O2          default_O2         floatzone_O2         |
|               runtime maxrss   runtime    maxrss  runtime      maxrss  |
|benchmark      median  median   median     median  median       median  |
+------------------------------------------------------------------------+
|400.perlbench  427      5517864 107        1235732 154          2893056 |
|401.bzip2      301      3581624 196        3448396 254          3550160 |
|403.gcc        237     13467288  83.9      4259380 163          8043360 |
|429.mcf        145      1935800 110        1718588 118          1718428 |
|433.milc       156       982764 130         697832 144          1020312 |
|444.namd       188        61280 121          49808 142            49892 |
|445.gobmk      285      1368400 182         152456 217          1062460 |
|447.dealII     214      1764156  99.8       816224 132          1664564 |
|450.soplex     120      1271488  76.5       564236  93.5        1231012 |
|453.povray     101       236780  44.5         7408  73.6         217624 |
|456.hmmer      236       814480 104          34004 164           607576 |
|458.sjeng      342       184764 196         180744 226           181428 |
|462.libquantum 135       366912 118         100732 123           334072 |
|464.h264ref    368       726084 156         117508 354           659368 |
|470.lbm         96.0     476048  78.5       421032  79.9         421040 |
|471.omnetpp    230       776404 121         175944 190           647448 |
|473.astar      224      1489504 157         473900 184          1118144 |
|482.sphinx3    282       413280 174          45752 229           446512 |
|483.xalancbmk  159      1472808  61.9       430504 129           831000 |
+------------------------------------------------------------------------+
|geomean        205       939084 114         278538 155           782220 |
+------------------------------------------------------------------------+
```

We can see that the ASan time overhead is `205/114=79%` while FloatZone is `155/114=36%`

### Juliet

1. Edit `runtime/wrap.c` and set the `CATCH_SEGFAULT` macro to 1 to enable segmentation faults to also be caught (as ASan does).
2. Enable **FloatzoneExt** by editing `env.sh` such that `FLOATZONE_MODE="floatzone double_sided just_size"`.
3. Make sure `env.sh` is loaded via `source env.sh`
4. Check `echo $FLOATZONE_MODE` is equal to `floatzone double_sided just_size`.
5. Run `./install.sh` to update the shared library.
6. Run the following commands:

```
python3 run.py run juliet floatzone_O0 --build --cwe 121
python3 run.py run juliet floatzone_O0 --build --cwe 122
python3 run.py run juliet floatzone_O0 --build --cwe 124
python3 run.py run juliet floatzone_O0 --build --cwe 126
python3 run.py run juliet floatzone_O0 --build --cwe 127
python3 run.py run juliet floatzone_O0 --build --cwe 415
python3 run.py run juliet floatzone_O0 --build --cwe 416
```

Note 1: Some Juliet test cases are random (their test case contains the word 'rand') and you may need to re-run multiple times for it to be caught.

Note 2: Juliet needs to compile with O0, so that's why we use `floatzone_O0`


## Troubleshooting

* Ensure `source env.sh` was executed in your terminal (with correct paths)
* Ensure evyerhting is up-to-date via `./install.sh`
* For FloatZone binaries, `run_base` must be present in the binary file name.
* Edit `wrap.c` depending on your needs (e.g. `SURVIVE_EXCEPTIONS=1`)
