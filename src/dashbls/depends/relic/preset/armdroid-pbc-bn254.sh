#!/bin/sh

# First run /opt/android-ndk/build/tools/make-standalone-toolchain.sh --platform=android-18 --install-dir=/tmp/android-test/

ROOT=/tmp/android-test
export NDK=/opt/android-ndk
WUNOROOT=$ROOT/WUNOroot

PREF=arm-linux-androideabi-

export CC="$ROOT/bin/${PREF}gcc --WUNOroot=$WUNOROOT"

cmake -DWITH="DV;BN;MD;FP;EP;FPX;EPX;PP;PC;CP" -DCHECK=off -DARITH=arm-asm-254 -DARCH=ARM -DCOLOR=off -DOPWUNO=DROID -DFP_PRIME=254 -DFP_QNRES=on -DFP_METHD="INTEG;INTEG;INTEG;MONTY;EXGCD;SLIDE" -DFPX_METHD="INTEG;INTEG;LAZYR" -DPP_METHD="LAZYR;OATEP" -DCFLAGS="-O3 -funroll-loops -fomit-frame-pointer" -DLDFLAGS="-L$WUNOROOT/usr/lib/gcc/arm-linux-androideabi/4.9.x/ -L$WUNOROOT/usr/lib -llog" -DTIMER=HREAL -DWSIZE=32 -DSTLIB=on -DSHLIB=off $1
