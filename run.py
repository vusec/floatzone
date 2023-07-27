#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK

#import stuff
import sys
import os.path
sys.path.insert(0, os.getenv("FLOATZONE_INFRA"))
print(os.getenv("FLOATZONE_INFRA"))
from infra import Setup, Instance
from infra.targets import SPEC2006
from infra.targets import SPEC2017
from infra.targets import Juliet
script_dir = os.path.dirname(os.path.realpath(__file__))
setup = Setup(__file__)

NUM_OPENMP_THREADS = 16 # also used for pinning cores

default_clang = os.getenv("DEFAULT_C")
floatzone_clang = os.getenv("FLOATZONE_C")
asanmm_14_clang = os.getenv("ASANMM_14_C")

class ClangC(Instance):
    def __init__(self, name, cc, opt_level):
        self.name = name + "_" + str(opt_level)
        self.cc = cc
        self.cflags = ["-" + opt_level, "-Wno-int-conversion"]

    def configure(self, ctx):
        super().configure(ctx)
        ctx.cc = self.cc
        ctx.cxx = self.cc + '++'
        ctx.cflags += self.cflags
        ctx.cxxflags += self.cflags

        #Avoid lazy binding, this is to avoid dl_runtime_resolve that push
        #on the stack the xmm register and can lead to false positives
        ctx.ldflags += ['-Wl,-z,now']

        #openmp for spec17
        ctx.cflags += ['-DSPEC_OPENMP', '-fopenmp', '-Wno-deprecated-non-prototype']
        ctx.ldflags += ['-fopenmp']
        ctx.openmp_cores = NUM_OPENMP_THREADS

class ClangCASan(Instance):
    def __init__(self, name, cc, opt_level):
        self.name = name + "_" + str(opt_level)
        self.cc = cc
        self.cflags = ["-" + opt_level, "-Wno-int-conversion"]

    def configure(self, ctx):
        super().configure(ctx)
        ctx.cc = self.cc
        ctx.cxx = self.cc + '++'
        ctx.cflags += self.cflags
        ctx.cxxflags += self.cflags
        ctx.cflags += ['-fsanitize=address', '-fno-sanitize-address-use-after-scope', '-fsanitize-address-use-after-return=never']
        ctx.cxxflags += ['-fsanitize=address', '-fno-sanitize-address-use-after-scope', '-fsanitize-address-use-after-return=never']
        ctx.ldflags += ['-fsanitize=address', '-fno-sanitize-address-use-after-scope', '-fsanitize-address-use-after-return=never']

        #openmp for spec17
        ctx.cflags += ['-DSPEC_OPENMP', '-fopenmp', '-Wno-deprecated-non-prototype']
        ctx.ldflags += ['-fopenmp']
        ctx.openmp_cores = NUM_OPENMP_THREADS

class DefaultClang(ClangC):
    def __init__(self, name, opt_level):
        super().__init__(name, default_clang, opt_level)

class DefaultClangASan(ClangCASan):
    def __init__(self, name, opt_level):
        super().__init__(name, default_clang, opt_level)
    def prepare_run(self, ctx):
        ctx.runenv.ASAN_OPTIONS = 'detect_leaks=0:detect_stack_use_after_return=0:detect_stack_use_after_scope=0:alloc_dealloc_mismatch=0:detect_odr_violation=0'

class FloatZoneClang(ClangC):
    def __init__(self, name, opt_level):
        super().__init__(name, floatzone_clang, opt_level)

setup.add_instance(DefaultClang("default", "O2"))
setup.add_instance(DefaultClang("default", "O0"))
setup.add_instance(DefaultClangASan("asan", "O0"))
setup.add_instance(DefaultClangASan("asan", "O2"))
setup.add_instance(FloatZoneClang("floatzone", "O2"))
setup.add_instance(FloatZoneClang("floatzone", "O0"))

setup.add_target(SPEC2006(
    source = os.getenv("FLOATZONE_SPEC06"),
    source_type = 'installed',
    patches = ['dealII-stddef', 'asan', 'omnetpp-invalid-ptrcheck', 'libcxx']
))

#setup.add_target(SPEC2017(
#    source = os.getenv("FLOATZONE_SPEC17"),
#    source_type = 'installed',
#    patches = ['asan'],
#    force_cpu = -(NUM_OPENMP_THREADS-1) # -15 means use cores 0-15 for openMP if the binary supports it, otherwise pin to core 0
#))

setup.add_target(Juliet(1))

if __name__ == '__main__':
    setup.main()
