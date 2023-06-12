#Must call this with `source env.sh`

#TODO specify all possible floatzone modes
export FLOATZONE_MODE="floatzone double_sided"

export FLOATZONE_TOP=/home/brb/floatzone

export FLOATZONE_LLVM=$FLOATZONE_TOP/floatzone-llvm-project/llvm/

export FLOATZONE_LLVM_BUILD=$FLOATZONE_TOP/llvm-floatzone/
export FLOATZONE_C=$FLOATZONE_LLVM_BUILD/bin/clang
export FLOATZONE_CXX=$FLOATZONE_LLVM_BUILD/bin/clang++

export DEFAULT_LLVM_BUILD=$FLOATZONE_TOP/llvm-default/
export DEFAULT_C=$DEFAULT_LLVM_BUILD/bin/clang
export DEFAULT_CXX=$DEFAULT_LLVM_BUILD/bin/clang++

export FLOATZONE_XED=$FLOATZONE_TOP/xed/
export FLOATZONE_XED_MBUILD=$FLOATZONE_TOP/mbuild/
export FLOATZONE_XED_LIB=$FLOATZONE_XED/obj/libxed.a
export FLOATZONE_XED_LIB_SO=$FLOATZONE_XED/obj/libxed.so
export FLOATZONE_XED_INC=$FLOATZONE_XED/include/public/xed/
export FLOATZONE_XED_INC_OBJ=$FLOATZONE_XED/obj/

export WRAP_DIR=$FLOATZONE_TOP/runtime/ 
export FLOATZONE_LIBWRAP_SO=$WRAP_DIR/libwrap.so

export FLOATZONE_SPEC06=$FLOATZONE_TOP/spec2006
export FLOATZONE_SPEC17=$FLOATZONE_TOP/spec2017

export FLOATZONE_INFRA=$FLOATZONE_TOP/instrumentation-infra/

#Suggested for better benchmarking
#echo "performance" | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
#echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
