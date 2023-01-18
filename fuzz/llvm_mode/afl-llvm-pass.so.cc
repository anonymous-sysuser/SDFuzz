/*
   american fuzzy lop - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault.

   Copyright 2015, 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This library is plugged into LLVM when invoking clang through afl-clang-fast.
   It tells the compiler to add code roughly equivalent to the bits discussed
   in ../afl-as.h.

 */

#define AFL_LLVM_PASS

#include "../config.h"
#include "../debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <list>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Analysis/CFGPrinter.h"

#if defined(LLVM34)
#include "llvm/DebugInfo.h"
#else
#include "llvm/IR/DebugInfo.h"
#endif

#if defined(LLVM34) || defined(LLVM35) || defined(LLVM36)
#define LLVM_OLD_DEBUG_API
#endif

using namespace llvm;

cl::opt<std::string> DistanceFile(
    "distance",
    cl::desc("Distance file containing the distance of each basic block to the provided targets."),
    cl::value_desc("filename")
);
cl::opt<std::string> TypeFile(
    "type",
    cl::desc("Type file containing the type of basic block."),
    cl::value_desc("type")
);

cl::opt<std::string> TargetsFile(
    "targets",
    cl::desc("Input file containing the target lines of code."),
    cl::value_desc("targets"));

cl::opt<std::string> OutDirectory(
    "outdir",
    cl::desc("Output directory where Ftargets.txt, Fnames.txt, and BBnames.txt are generated."),
    cl::value_desc("outdir"));

namespace llvm {

template<>
struct DOTGraphTraits<Function*> : public DefaultDOTGraphTraits {
  DOTGraphTraits(bool isSimple=true) : DefaultDOTGraphTraits(isSimple) {}

  static std::string getGraphName(Function *F) {
    return "CFG for '" + F->getName().str() + "' function";
  }

  std::string getNodeLabel(BasicBlock *Node, Function *Graph) {
    if (!Node->getName().empty()) {
      return Node->getName().str();
    }

    std::string Str;
    raw_string_ostream OS(Str);

    Node->printAsOperand(OS, false);
    return OS.str();
  }
};

} // namespace llvm

namespace {

  class AFLCoverage : public ModulePass {

    public:

      static char ID;
      AFLCoverage() : ModulePass(ID) { }

      bool runOnModule(Module &M) override;

      // StringRef getPassName() const override {
      //  return "American Fuzzy Lop Instrumentation";
      // }

  };

}

char AFLCoverage::ID = 0;

static void getDebugLoc(const Instruction *I, std::string &Filename,
                        unsigned &Line) {
#ifdef LLVM_OLD_DEBUG_API
  DebugLoc Loc = I->getDebugLoc();
  if (!Loc.isUnknown()) {
    DILocation cDILoc(Loc.getAsMDNode(M.getContext()));
    DILocation oDILoc = cDILoc.getOrigLocation();

    Line = oDILoc.getLineNumber();
    Filename = oDILoc.getFilename().str();

    if (filename.empty()) {
      Line = cDILoc.getLineNumber();
      Filename = cDILoc.getFilename().str();
    }
  }
#else
  if (DILocation *Loc = I->getDebugLoc()) {
    Line = Loc->getLine();
    Filename = Loc->getFilename().str();

    if (Filename.empty()) {
      DILocation *oDILoc = Loc->getInlinedAt();
      if (oDILoc) {
        Line = oDILoc->getLine();
        Filename = oDILoc->getFilename().str();
      }
    }
  }
#endif /* LLVM_OLD_DEBUG_API */
}

static bool isBlacklisted(const Function *F) {
  static const SmallVector<std::string, 8> Blacklist = {
    "asan.",
    "llvm.",
    "sancov.",
    "__ubsan_handle_",
    "free",
    "malloc",
    "calloc",
    "realloc"
  };

  for (auto const &BlacklistFunc : Blacklist) {
    if (F->getName().startswith(BlacklistFunc)) {
      return true;
    }
  }

  return false;
}

bool AFLCoverage::runOnModule(Module &M) {

  bool is_aflgo = false;
  bool is_aflgo_preprocessing = false;

  if (!TargetsFile.empty() && !DistanceFile.empty()) {
    FATAL("Cannot specify both '-targets' and '-distance'!");
    return false;
  }

  std::list<std::string> targets;
  std::map<std::string, std::string> callsites; // loc => func name
  std::map<std::string, int> bb_to_dis;
  std::map<std::string, std::tuple<int, std::string>> bb_to_type;
  std::map<std::string, int32_t> function_to_ID;
  std::vector<std::string> basic_blocks;
  std::vector<std::string> type_basic_blocks;
  int32_t function_ID = 1;

  if (!TargetsFile.empty()) {

    if (OutDirectory.empty()) {
      FATAL("Provide output directory '-outdir <directory>'");
      return false;
    }

    std::ifstream targetsfile(TargetsFile);
    std::string line;
    std::size_t pos(0);
    std::string loc("");
    std::string name("");
    while (std::getline(targetsfile, line)) {
      if(!line.empty()) {
        pos = line.find(",");
        loc = line.substr(0, pos);
        name = line.substr(pos + 1, line.length());
        callsites.emplace(loc, name);
        SAYF(cCYA "aflgo-llvm-pass (pro-processing!) " cBRI VERSION cRST " (scanning callsites: loc %s; calleename %s)\n", loc.c_str(), name.c_str());
      }
      else{
        targets.push_back(loc);
        SAYF(cCYA "aflgo-llvm-pass (pro-processing!) " cBRI VERSION cRST " (push targets: loc %s;)\n", loc.c_str());
      }
    }
    targets.push_back(loc);
    SAYF(cCYA "aflgo-llvm-pass (pro-processing!) " cBRI VERSION cRST " (push targets: loc %s;)\n", loc.c_str());
    targetsfile.close();

    is_aflgo_preprocessing = true;

  } else if (!DistanceFile.empty()) {

    std::ifstream cf(DistanceFile);
    if (cf.is_open()) {

      std::string line;
      while (getline(cf, line)) {

        std::size_t pos = line.find(",");
        std::string bb_name = line.substr(0, pos);
        int bb_dis = (int) (100.0 * atof(line.substr(pos + 1, line.length()).c_str()));

        bb_to_dis.emplace(bb_name, bb_dis);
        basic_blocks.push_back(bb_name);

      }
      cf.close();

      is_aflgo = true;

    } else {
      FATAL("Unable to find %s.", DistanceFile.c_str());
      return false;
    }
    std::ifstream scf(TypeFile);
    if (scf.is_open()) {

      std::string line;
      while (getline(scf, line)) {

        std::size_t pos = line.find(",");
        std::string bb_name = line.substr(0, pos);
        std::size_t pos1 = line.find_last_of(",");
        int bb_type = (int) atoi(line.substr(pos + 1, pos1).c_str());// type can be 1, 2, or 3
        std::string tmpname = line.substr(pos1 + 1, line.length());
        SAYF(cCYA "aflgo-llvm-pass (yeah!) " cBRI VERSION cRST " (scanning: bb_name %s; bb_type %d; calleename %s)\n", bb_name.c_str(), bb_type, tmpname.c_str());

        bb_to_type.emplace(bb_name, std::make_tuple(bb_type, tmpname));
        type_basic_blocks.push_back(bb_name);
      }
      scf.close();
    } else {
      FATAL("Unable to find %s.", TypeFile.c_str());
      return false;
    }

  }

  /* Show a banner */

  char be_quiet = 0;

  if (isatty(2) && !getenv("AFL_QUIET")) {

    if (is_aflgo || is_aflgo_preprocessing)
      SAYF(cCYA "aflgo-llvm-pass (yeah!) " cBRI VERSION cRST " (%s mode)\n",
           (is_aflgo_preprocessing ? "preprocessing" : "distance instrumentation"));
    else
      SAYF(cCYA "afl-llvm-pass " cBRI VERSION cRST " by <lszekeres@google.com>\n");


  } else be_quiet = 1;

  /* Decide instrumentation ratio */

  char* inst_ratio_str = getenv("AFL_INST_RATIO");
  unsigned int inst_ratio = 100;

  if (inst_ratio_str) {

    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");

  }

  /* Default: Not selective */
  char* is_selective_str = getenv("AFLGO_SELECTIVE");
  unsigned int is_selective = 0;

  if (is_selective_str && sscanf(is_selective_str, "%u", &is_selective) != 1)
    FATAL("Bad value of AFLGO_SELECTIVE (must be 0 or 1)");

  char* dinst_ratio_str = getenv("AFLGO_INST_RATIO");
  unsigned int dinst_ratio = 100;

  if (dinst_ratio_str) {

    if (sscanf(dinst_ratio_str, "%u", &dinst_ratio) != 1 || !dinst_ratio ||
        dinst_ratio > 100)
      FATAL("Bad value of AFLGO_INST_RATIO (must be between 1 and 100)");

  }

  /* Instrument all the things! */

  int inst_blocks = 0;

  if (is_aflgo_preprocessing) {

    std::ofstream bbnames(OutDirectory + "/BBnames.txt", std::ofstream::out | std::ofstream::app);
    std::ofstream bbcalls(OutDirectory + "/BBcalls.txt", std::ofstream::out | std::ofstream::app);
    std::ofstream bbcalltargets(OutDirectory + "/BBcalltargets.txt", std::ofstream::out | std::ofstream::app);
    std::ofstream fnames(OutDirectory + "/Fnames.txt", std::ofstream::out | std::ofstream::app);
    std::ofstream ftargets(OutDirectory + "/Ftargets.txt", std::ofstream::out | std::ofstream::app);

    /* Create dot-files directory */
    std::string dotfiles(OutDirectory + "/dot-files");
    if (sys::fs::create_directory(dotfiles)) {
      FATAL("Could not create directory %s.", dotfiles.c_str());
    }

    for (auto &F : M) {

      bool has_BBs = false;
      std::string funcName = F.getName().str();

      /* Black list of function names */
      if (isBlacklisted(&F)) {
        continue;
      }

      bool is_target = false;
      //bool is_callsite = false;
      for (auto &BB : F) {

        std::string bb_name("");
        std::string filename;
        unsigned line;

        for (auto &I : BB) {
          getDebugLoc(&I, filename, line);

          /* Don't worry about external libs */
          static const std::string Xlibs("/usr/");
          if (filename.empty() || line == 0 || !filename.compare(0, Xlibs.size(), Xlibs))
            continue;

          if (bb_name.empty()) {

            std::size_t found = filename.find_last_of("/\\");
            if (found != std::string::npos)
              filename = filename.substr(found + 1);

            bb_name = filename + ":" + std::to_string(line);
          }

          if(!is_target) {
              for (auto &target : targets) {
                std::size_t found = target.find_last_of("/\\");
                if (found != std::string::npos)
                  target = target.substr(found + 1);

                std::size_t pos = target.find_last_of(":");
                std::string target_file = target.substr(0, pos);
                unsigned int target_line = atoi(target.substr(pos + 1).c_str());

                if (!target_file.compare(filename) && target_line == line) {
                  is_target = true;
                }
              }
          }

          std::map<std::string,std::string>::iterator it;
          for (it = callsites.begin(); it !=callsites.end(); ++it) {
                std::string callsite = it->first;
                std::size_t found = callsite.find_last_of("/\\");
                if (found != std::string::npos)
                  callsite = callsite.substr(found + 1);

                std::size_t pos = callsite.find_last_of(":");
                std::string callsite_file = callsite.substr(0, pos);
                unsigned int callsite_line = atoi(callsite.substr(pos + 1).c_str());

                if (!callsite_file.compare(filename) && callsite_line == line) {
                  bbcalltargets << bb_name << ","<< it->second<< "\n";
                  //is_callsite = true;
                }
            }

            if (auto *c = dyn_cast<CallInst>(&I)) {

              std::size_t found = filename.find_last_of("/\\");
              if (found != std::string::npos)
                filename = filename.substr(found + 1);

              if (auto *CalledF = c->getCalledFunction()) {
                if (!isBlacklisted(CalledF))
                  bbcalls << bb_name << "," << CalledF->getName().str() << "\n";
              }
            }
        }

        if (!bb_name.empty()) {

          BB.setName(bb_name + ":");
          if (!BB.hasName()) {
            std::string newname = bb_name + ":";
            Twine t(newname);
            SmallString<256> NameData;
            StringRef NameRef = t.toStringRef(NameData);
            MallocAllocator Allocator;
            BB.setValueName(ValueName::Create(NameRef, Allocator));
          }

          bbnames << BB.getName().str() << "\n";
          has_BBs = true;

#ifdef AFLGO_TRACING
          auto *TI = BB.getTerminator();
          IRBuilder<> Builder(TI);

          Value *bbnameVal = Builder.CreateGlobalStringPtr(bb_name);
          Type *Args[] = {
              Type::getInt8PtrTy(M.getContext()) //uint8_t* bb_name
          };
          FunctionType *FTy = FunctionType::get(Type::getVoidTy(M.getContext()), Args, false);
          Constant *instrumented = M.getOrInsertFunction("llvm_profiling_call", FTy);
          Builder.CreateCall(instrumented, {bbnameVal});
#endif

        }
      }

      if (has_BBs) {
        /* Print CFG */
        std::string cfgFileName = dotfiles + "/cfg." + funcName + ".dot";
        std::error_code EC;
        raw_fd_ostream cfgFile(cfgFileName, EC, sys::fs::F_None);
        if (!EC) {
          WriteGraph(cfgFile, &F, true);
        }

        if (is_target)
          ftargets << F.getName().str() << "\n";
        fnames << F.getName().str() << "\n";
      }
    }
  } else {
    /* Distance instrumentation */

    LLVMContext &C = M.getContext();
    IntegerType *Int8Ty  = IntegerType::getInt8Ty(C);
    IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
    IntegerType *Int64Ty = IntegerType::getInt64Ty(C);

#ifdef __x86_64__
    IntegerType *LargestType = Int64Ty;
    ConstantInt *MapCntLoc = ConstantInt::get(LargestType, MAP_SIZE + 8);
#else
    IntegerType *LargestType = Int32Ty;
    ConstantInt *MapCntLoc = ConstantInt::get(LargestType, MAP_SIZE + 4);
#endif
    ConstantInt *MapDistLoc = ConstantInt::get(LargestType, MAP_SIZE);
    ConstantInt *One = ConstantInt::get(LargestType, 1);

    /* Get globals for the SHM region and the previous location. Note that
       __afl_prev_loc is thread-local. */

    GlobalVariable *AFLMapPtr =
        new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                           GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

    GlobalVariable *AFLPrevLoc = new GlobalVariable(
        M, Int32Ty, false, GlobalValue::ExternalLinkage, 0, "__afl_prev_loc",
        0, GlobalVariable::GeneralDynamicTLSModel, 0, false);

    for (auto &F : M) {

      int distance = -1;
      int bbtype = -1;
      std::string tempname;
      std::string funcName = F.getName().str();

      for (auto &BB : F) {

        distance = -1;
        bbtype = -1;
        if (is_aflgo) {

          std::string bb_name;
          for (auto &I : BB) {
            std::string filename;
            unsigned line;
            getDebugLoc(&I, filename, line);

            if (filename.empty() || line == 0)
              continue;
            // compute bb_name when it is not available yet, only once
            std::size_t found = filename.find_last_of("/\\");
            if (found != std::string::npos)
              filename = filename.substr(found + 1);

            bb_name = filename + ":" + std::to_string(line);
            break;
          }
          // TODO \sys new fuzzer


          if (!bb_name.empty()) {

            if (find(basic_blocks.begin(), basic_blocks.end(), bb_name) == basic_blocks.end()) {

              if (is_selective)
                continue;

            } else {

              /* Find distance for BB */

              if (AFL_R(100) < dinst_ratio) {
                std::map<std::string,int>::iterator it;
                for (it = bb_to_dis.begin(); it != bb_to_dis.end(); ++it)
                  if (it->first.compare(bb_name) == 0)
                    distance = it->second;

              }
            }

            // \sys new impl
            if (find(type_basic_blocks.begin(), type_basic_blocks.end(), bb_name) == type_basic_blocks.end()) {
            } else {

              /* Find type for BB */
              std::map<std::string, std::tuple<int, std::string>>::iterator it;
              for (it = bb_to_type.begin(); it != bb_to_type.end(); ++it)
                if (it->first.compare(bb_name) == 0) {
                  bbtype = std::get<0>(it->second);
                  tempname = std::get<1>(it->second);
                  SAYF(cCYA "aflgo-llvm-pass (processing!) " cBRI VERSION cRST " (find bbtype:  %d; Fcalleename %s)\n", bbtype, tempname.c_str());
                  break;
                }
              }
          }



        // if bbtype == 1. need to do sth with callsite.
        // if bbtype == 2. selective termiante?
        if(bbtype == 1) {

          // find the callsite instruction
          for (auto &I: BB) {
            if (auto *c = dyn_cast<CallInst> (&I)) {
              if(auto *callee = c->getCalledFunction()) {
                std::string calleeName = callee->getName().str();
                // get the calleename fro mfile and comapre to calleeName
                std::size_t found = calleeName.find_last_of(tempname);
                // check the callee is equal to the function we want.
                if (found != std::string::npos){
                SAYF(cCYA "aflgo-llvm-pass (processing!) " cBRI VERSION cRST " (insert for bbtype %d @ %s)\n", bbtype, bb_name.c_str());
                /* before
                 * check top function on stack == current and with status 0,
                 *    1). change it to 1
                 *    2). push calle status with 0
                 * otherwise, do nothing
                 *
                 *
                 * invoke checkbeforecallsite() before the callsite/instruction.
                */
                  IRBuilder<> callIRB(&I);
                  callIRB.SetInsertPoint(&I);
                  Type *args[] = {Int32Ty, Int32Ty};
                  FunctionType *sig= FunctionType::get(Type::getVoidTy(M.getContext()), args, false);
                  auto checkbefore = M.getOrInsertFunction("checkbeforecallsite", sig);
                int32_t callercode = -1;
                int32_t calleecode = -1;
                std::map<std::string,int>::iterator it;
                for (it = function_to_ID.begin(); it != function_to_ID.end(); ++it) {
                  if (it->first.compare(funcName) == 0)
                    callercode = it->second;
                  if (it->first.compare(calleeName) == 0)
                    calleecode = it->second;
                }
                if (callercode == -1) {
                  callercode = function_ID << 4;
                  function_to_ID.emplace(funcName, callercode);
                  function_ID ++;
                }

                if (calleecode == -1) {
                  calleecode = function_ID << 4;
                  function_to_ID.emplace(calleeName, calleecode);
                  function_ID ++;
                }

                SAYF(cCYA "aflgo-llvm-pass (processing!) " cBRI VERSION cRST " callercode: %x; caleecode: %x\n", callercode, calleecode);
                callIRB.CreateCall(checkbefore, {ConstantInt::get(Int32Ty, callercode), ConstantInt::get(Int32Ty, calleecode)});

                /* after, if still not exit(0)
                 * check top function on statck == callee
                 *    1). pop it
                 * otherwise do nothing
                 *
                 * invoke checkaftercallsite() before the callsite/instruction.
                 */ 
                  // after the callsite
                  callIRB.SetInsertPoint(I.getNextNode());
                  auto checkafter = M.getOrInsertFunction("checkaftercallsite", sig);
                  callIRB.CreateCall(checkafter, {ConstantInt::get(Int32Ty, callercode), ConstantInt::get(Int32Ty, calleecode)});
                  break;
                } // end for found
              } // end for calledname
            } // end for callinst
          } //end for I in BB
        }
        else if(bbtype == 2 || bbtype == 3) {
          BasicBlock::iterator ip = BB.getFirstInsertionPt();
          IRBuilder<> callIRB(&(*ip));
          Type *args[] = {Int32Ty};
          FunctionType *sig= FunctionType::get(Type::getVoidTy(M.getContext()), args, false);
          int32_t callercode = -1;
          std::map<std::string,int>::iterator it;
          for (it = function_to_ID.begin(); it != function_to_ID.end(); ++it) {
            if (it->first.compare(funcName) == 0) {
              callercode = it->second;
              break;
            }
          }
          if (callercode == -1) {
            callercode = function_ID << 4;
            function_to_ID.emplace(funcName, callercode);
            function_ID ++;
          }
          SAYF(cCYA "aflgo-llvm-pass (processing!) " cBRI VERSION cRST " (insert for bbtype %d @ %s)\n", bbtype, bb_name.c_str());
          SAYF(cCYA "aflgo-llvm-pass (processing!) " cBRI VERSION cRST " callercode: %x\n", callercode);

          if(bbtype == 3) {
            // initialize main function
            auto checkmain = M.getOrInsertFunction("checkmain", sig);
            callIRB.CreateCall(checkmain, {ConstantInt::get(Int32Ty, callercode)});
          }
          else{
            /* somewhere we need to early terminate for BB
             * check top function on stack == current, terminate it
             * 
             * invoke checkterminate at the beginning of the BBs
             */
            auto checkterminate = M.getOrInsertFunction("checkterminate", sig);
            callIRB.CreateCall(checkterminate, {ConstantInt::get(Int32Ty, callercode)});
          }
        }
        }

        BasicBlock::iterator IP = BB.getFirstInsertionPt();
        IRBuilder<> IRB(&(*IP));

        if (AFL_R(100) >= inst_ratio) continue;

        /* Make up cur_loc */

        unsigned int cur_loc = AFL_R(MAP_SIZE);

        ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);

        /* Load prev_loc */

        LoadInst *PrevLoc = IRB.CreateLoad(AFLPrevLoc);
        PrevLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, IRB.getInt32Ty());

        /* Load SHM pointer */

        LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
        MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *MapPtrIdx =
            IRB.CreateGEP(MapPtr, IRB.CreateXor(PrevLocCasted, CurLoc));

        /* Update bitmap */

        LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
        Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *Incr = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
        IRB.CreateStore(Incr, MapPtrIdx)
           ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        /* Set prev_loc to cur_loc >> 1 */

        StoreInst *Store =
            IRB.CreateStore(ConstantInt::get(Int32Ty, cur_loc >> 1), AFLPrevLoc);
        Store->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        if (distance >= 0) {

          ConstantInt *Distance =
              ConstantInt::get(LargestType, (unsigned) distance);

          /* Add distance to shm[MAPSIZE] */

          Value *MapDistPtr = IRB.CreateBitCast(
              IRB.CreateGEP(MapPtr, MapDistLoc), LargestType->getPointerTo());
          LoadInst *MapDist = IRB.CreateLoad(MapDistPtr);
          MapDist->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

          Value *IncrDist = IRB.CreateAdd(MapDist, Distance);
          IRB.CreateStore(IncrDist, MapDistPtr)
              ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

          /* Increase count at shm[MAPSIZE + (4 or 8)] */

          Value *MapCntPtr = IRB.CreateBitCast(
              IRB.CreateGEP(MapPtr, MapCntLoc), LargestType->getPointerTo());
          LoadInst *MapCnt = IRB.CreateLoad(MapCntPtr);
          MapCnt->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

          Value *IncrCnt = IRB.CreateAdd(MapCnt, One);
          IRB.CreateStore(IncrCnt, MapCntPtr)
              ->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

        }

        inst_blocks++;

      }
    }
  }

  /* Say something nice. */

  if (!is_aflgo_preprocessing && !be_quiet) {

    if (!inst_blocks) WARNF("No instrumentation targets found.");
    else OKF("Instrumented %u locations (%s mode, ratio %u%%, dist. ratio %u%%).",
             inst_blocks,
             getenv("AFL_HARDEN")
             ? "hardened"
             : ((getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN"))
               ? "ASAN/MSAN" : "non-hardened"),
             inst_ratio, dinst_ratio);

  }

  return true;

}


static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

  PM.add(new AFLCoverage());

}


static RegisterStandardPasses RegisterAFLPass(
    PassManagerBuilder::EP_OptimizerLast, registerAFLPass);

static RegisterStandardPasses RegisterAFLPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAFLPass);
