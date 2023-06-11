#!/bin/bash
BAK_DIR=$(pwd)
set -e
unset FLOATZONE_MODE

#Check we loaded env.sh
if [ -z $FLOATZONE_C ]
then
  echo $FLOATZONE_C
  echo "Env variables not found!"
  exit 1
fi

#Checking if LLVM default is present
if [[ ! -f $DEFAULT_C ]]
then
  mkdir -p $DEFAULT_LLVM_BUILD
  cd $DEFAULT_LLVM_BUILD
  cmake -DLLVM_ENABLE_PROJECTS="clang;compiler-rt;openmp" -DCMAKE_CXX_FLAGS=-DDEFAULTCLANG -DCMAKE_BUILD_TYPE=Release -GNinja -DLLVM_PARALLEL_LINK_JOBS=1 -DLLVM_TARGETS_TO_BUILD="X86" -DCLANG_ENABLE_STATIC_ANALYZER=OFF -DCLANG_ENABLE_ARCMT=OFF $FLOATZONE_LLVM 
  ninja

  cp $DEFAULT_LLVM_BUILD/projects/openmp/runtime/src/omp.h $DEFAULT_LLVM_BUILD/lib/clang/14.0.6/include
fi

#Checking Floatzone LLVM is present and compiled
if [[ ! -f $FLOATZONE_C ]]
then
  #Doing the cmake of LLVM
  mkdir -p $FLOATZONE_LLVM_BUILD
  cd $FLOATZONE_LLVM_BUILD
  cmake -DLLVM_ENABLE_PROJECTS="clang;compiler-rt;openmp" -DCMAKE_BUILD_TYPE=Release -GNinja -DLLVM_PARALLEL_LINK_JOBS=1 -DLLVM_TARGETS_TO_BUILD="X86" -DCLANG_ENABLE_STATIC_ANALYZER=OFF -DCLANG_ENABLE_ARCMT=OFF $FLOATZONE_LLVM 
  ninja

  cp $FLOATZONE_LLVM_BUILD/projects/openmp/runtime/src/omp.h $FLOATZONE_LLVM_BUILD/lib/clang/14.0.6/include
fi

#Always compile LLVM
cd $FLOATZONE_LLVM_BUILD
ninja

# If after compilation we still do not have clang, abort
if [[ ! -f $FLOATZONE_C ]]
then
  echo "Missing clang, ABORT"
  exit -1
fi

# Check XED
if [[ ! -f $FLOATZONE_XED_LIB_SO ]]
then
  echo "Missing libxed.so, compiling it"
  cd $FLOATZONE_XED
  ./mfile.py --shared #--extra-flags=-fPIC

  if [[ ! -f $FLOATZONE_XED_LIB_SO ]]
  then
    echo "Missing libxed.so, ABORT"
    exit -1
  fi
fi

#Always compile wrap.so
cd $WRAP_DIR
make
if [[ ! -f $FLOATZONE_LIBWRAP_SO ]]
then
  echo "Missing libwrap.so, ABORT"
  exit -1
fi

#Check if SPEC2006 is installed
#if [[ ! -d $FLOATZONE_SPEC06 ]]
#then
#  echo "Missing spec 2006 installation"
#  mkdir -p /tmp/spec06
#  sudo mount -o loop $FLOATZONE_SPEC06_ISO /tmp/spec06
#  cd /tmp/spec06
#  ./install.sh -f -d $FLOATZONE_SPEC06
#  sudo umount /tmp/spec06
#fi
#
##Check if SPEC2017 is installed
#if [[ ! -d $FLOATZONE_SPEC17 ]]
#then
#  echo "Missing spec 2017 installation"
#  mkdir -p /tmp/spec17
#  sudo mount -o loop $FLOATZONE_SPEC17_ISO /tmp/spec17
#  cd /tmp/spec17
#  ./install.sh -f -d $FLOATZONE_SPEC17
#  sudo umount /tmp/spec17
#fi
#
##install asan-- 14
#if [[ ! -f $ASANMM_14_C ]]
#then
#  cd $ASANMM_LLVM_14
#  mkdir -p $ASANMM_LLVM_14_BUILD
#  cd $ASANMM_LLVM_14_BUILD
#  cmake -DLLVM_ENABLE_PROJECTS="clang;compiler-rt;openmp" -DCMAKE_BUILD_TYPE=Release -GNinja -DLLVM_PARALLEL_LINK_JOBS=1 \
#  -DLLVM_TARGETS_TO_BUILD="X86" -DCLANG_ENABLE_STATIC_ANALYZER=OFF -DCLANG_ENABLE_ARCMT=OFF ../llvm 
#  ninja
#  cp $ASANMM_LLVM_14_BUILD/projects/openmp/runtime/src/omp.h $ASANMM_LLVM_14_BUILD/lib/clang/14.0.6/include
#fi
#
##install rezzan 14
#if [[ ! -f $REZZAN_CC ]]
#then
#    cd $REZZAN_TOP 
#    PATH_BAK=$PATH
#    export PATH="$DEFAULT_LLVM_BUILD/bin/:$PATH"
#    unset FLOATZONE_MODE
#    ./install.sh 
#    export PATH=$PATH_BAK
#fi
#
##install all AFL++s
#if [[ ! -f $AFLPP_FLOATZONE/afl-cc ]]
#then
#    cd $AFLPP_FLOATZONE
#    PATH_BAK=$PATH
#    export PATH="$FLOATZONE_LLVM_BUILD/bin/:$PATH"
#    unset FLOATZONE_MODE
#    make clean
#    make -j
#    export PATH=$PATH_BAK
#fi
#
#if [[ ! -f $AFLPP_ASANMM/afl-cc ]]
#then
#    cd $AFLPP_ASANMM
#    PATH_BAK=$PATH
#    export PATH="$ASANMM_LLVM_14_BUILD/bin/:$PATH"
#    make clean
#    make -j
#    export PATH=$PATH_BAK
#fi
#
#if [[ ! -f $AFLPP_REZZAN/afl-cc ]]
#then
#    cd $AFLPP_REZZAN
#    PATH_BAK=$PATH
#    export PATH="$DEFAULT_LLVM_BUILD/bin/:$PATH"
#    unset FLOATZONE_MODE
#    make clean
#    make -j
#    export PATH=$PATH_BAK
#fi
#
cd $BAK_DIR
