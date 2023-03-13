# SDFuzz
SDFuzz is a directed fuzzing tool driven by target states. SDFuzz uses the target call stacks and the reaching order of the target sites to improve the testing efficiency.SDFuzz first automatically extracts target states in vulnerability reports and static analysis results. SDFuzz employs a selective instrumentation technique to reduce the fuzzing scope to the required code for achieving target states. SDFuzz then early terminates the execution of a test case once SDFuzz probes the remaining execution cannot achieve the target states. It further uses a new target state feedback and refines prior imprecise distance metric into a two-dimensional feedback mechanism to proactively drive the exploration towards the target states.

## Setup
- Build the fuzzer component

    SDFuzz uses an standard fuzzing component just like AFL (AFLGo). Follow the instructions in the [fuzz directory](fuzz/README.md) for details.

-  Build SVF

    SDFuzz can incorporate with SVF to validates its results. 
    ```sh
    git clone https://github.com/SVF-tools/SVF.git
    cd SVF
    source ./build.sh # this builds SVF using cmake
    ```
    Interested readers can refer to [SVF-Setup-Guide](https://github.com/svf-tools/SVF/wiki/Setup-Guide#getting-started) for other installation instructions.

## Run

- Extract the target states
    
    A simple python script is given to extract target states from vulnerability reports.
    ```sh
    python3 parseTrace.py [-t trace.txt] [-o target.out]
    ```
    
    Additionally, to extract the target states for SVF, you should first use SVF to analyze an program and generate the results.
    ```sh
    python3 parseSVF.py [-t result-directory] [-o target.out]
    ```

- Instrument the target program with target states.=

    Compute basic block distances
    ```sh
    # Set aflgo-instrumenter
    export CC=$AFLGO/afl-clang-fast
    export CXX=$AFLGO/afl-clang-fast++
    # provide the target states file for the fuzzer to perform instrumentation 
    # Set aflgo-instrumentation flags
    export COPY_CFLAGS=$CFLAGS
    export COPY_CXXFLAGS=$CXXFLAGS
    export ADDITIONAL="-targets=$TMP_DIR/BBtargets.txt -outdir=$TMP_DIR -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
    export CFLAGS="$CFLAGS $ADDITIONAL"
    export CXXFLAGS="$CXXFLAGS $ADDITIONAL"

    # Build libxml2 (in order to generate CG and CFGs).
    # Meanwhile go have a coffee ☕️
    export LDFLAGS=-lpthread
    pushd $SUBJECT
    ./autogen.sh
    ./configure --disable-shared
    make clean
    make xmllint
    popd
    # * If the linker (CCLD) complains that you should run ranlib, make
    #   sure that libLTO.so and LLVMgold.so (from building LLVM with Gold)
    #   can be found in /usr/lib/bfd-plugins
    # * If the compiler crashes, there is some problem with LLVM not 
    #   supporting our instrumentation (afl-llvm-pass.so.cc:540-577).
    #   LLVM has changed the instrumentation-API very often :(
    #   -> Check LLVM-version, fix problem, and prepare pull request.
    # * You can speed up the compilation with a parallel build. However,
    #   this may impact which BBs are identified as targets. 
    #   See https://github.com/aflgo/aflgo/issues/41.


    # Test whether CG/CFG extraction was successful
    $SUBJECT/xmllint --valid --recover $SUBJECT/test/dtd3
    ls $TMP_DIR/dot-files
    echo "Function targets"
    cat $TMP_DIR/Ftargets.txt

    # Clean up
    cat $TMP_DIR/BBnames.txt | rev | cut -d: -f2- | rev | sort | uniq > $TMP_DIR/BBnames2.txt && mv $TMP_DIR/BBnames2.txt $TMP_DIR/BBnames.txt
    cat $TMP_DIR/BBcalls.txt | sort | uniq > $TMP_DIR/BBcalls2.txt && mv $TMP_DIR/BBcalls2.txt $TMP_DIR/BBcalls.txt

    $AFLGO/script/parseTrace.py -t TRACE -o $TMP_DIR/targets.txt
    cd tool/joern/
    ./joern-parse PROGRAM #by default generates ./cpg.bin
    ./joern-export --repr cdg --out CDG
    ./joern-export --repr cdg --out AST

    # Generate distance ☕️
    # $AFLGO/scripts/genDistance.sh is the original, but significantly slower, version
    $AFLGO/scripts/genDistance.sh $SUBJECT $TMP_DIR xmllint

    # Check distance file
    echo "Distance values:"
    head -n5 $TMP_DIR/distance.cfg.txt
    echo "..."
    tail -n5 $TMP_DIR/distance.cfg.txt
    ```

    Put the `target.out` to `fuzz/llvm-mode/` and compile the program again but not in the preprocessing mode.


- Start the fuzzer

SDFuzz uses the same command line options as other fuzzers. You can specifcy the initial seeds and output directory, etc.


