#!/bin/sh
# SPDX-License-Identifier: ISC
# Build the libFuzzer harnesses with clang, AddressSanitizer and UndefinedBehaviorSanitizer.
# usage: build.sh OUTDIR
set -eu
here=$(cd "$(dirname "$0")" && pwd)
src=$here/../../src
out=$1
mkdir -p "$out"
flags="-g -O1 -fno-omit-frame-pointer -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all -I$src -I$here"
provider="$src/provider.c $src/keymgmt.c $src/decoder.c $src/signature.c $src/verify.c"
${CC:-clang} $flags -o "$out/fuzz-spki" "$here/fuzz-spki.c" $provider -lcrypto
${CC:-clang} $flags -o "$out/fuzz-verify" "$here/fuzz-verify.c" $provider -lcrypto
${CC:-clang} $flags -DED521_FUZZ_FIXED_V7 -o "$out/fuzz-verify-v7" "$here/fuzz-verify.c" $provider -lcrypto
${CC:-clang} $flags -o "$out/fuzz-x509-verify" "$here/fuzz-x509-verify.c" $provider -lcrypto
