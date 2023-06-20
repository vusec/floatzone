#Must call this with `source env.sh`

#FLOATZONE_MODE is used at compile time to configure the detection
#capabilities:
# - floatzone : enable FloatZone
# - double_sided : include underflow redzone
# - just_size : enable FloatZoneExt

#--- FloatZone ---
export FLOATZONE_MODE="floatzone double_sided"
#--- FloatZoneExt ---
#export FLOATZONE_MODE="floatzone double_sided just_size"

#CHANGME depending on where you cloned the floatzone repo!
export FLOATZONE_TOP=/home/sec23_ae/floatzone

#CHANGME depending on where you installed SPEC
export FLOATZONE_SPEC06=/home/sec23_ae/spec06

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


export FLOATZONE_INFRA=$FLOATZONE_TOP/instrumentation-infra/

#Suggested for better benchmarking
#echo "performance" | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
#echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
