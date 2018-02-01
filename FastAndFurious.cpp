/** 
 *  @file    FastAndFurious.cpp
 *  @author  Alberto Ros (aros@um.es)
 *  
 *  @section DESCRIPTION
 *  
 *  A Pin tool that check for data races. 
 *  It requires the synchronization to be exposed to the Pin tool through the 
 *  funcions calls whose names are in the Routine function. 
 *
 */

#include "pin.H"
#include "AddressUtil.h"
#include "Value.h"
#include "DataBlock.h"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <set>

//#define DEBUG_WITH_GDB // use -appdebug with pin

PIN_LOCK lock;
map <Address, DataBlock> values_cache[PIN_MAX_THREADS];
map <Address, DataBlock> values_memory;
map <Address, DataBlock> values_SC;
int num_threads = 0, my_max_num_threads = 0;
bool check_thread[PIN_MAX_THREADS];
bool in_sync[PIN_MAX_THREADS];
set<Address> racy_addr_set;
int num_barriers = 0, num_locks = 0, num_signals = 0;
 
struct debug_info {
  INT32 column, line, core;
  string filename;
};
map <Address, debug_info> last_write_SC;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
			    "o", "consistency-checker-RC.out", "specify output file name");

void initialization() {
  racy_addr_set.clear();
}

/* ===================================================================== */

vector<string> FilteredImages;
set<UINT32> FilteredImageIds;

void InitFilteredImages() {
  FilteredImages.push_back("ld-linux.so");
  FilteredImages.push_back("ld-linux-x86-64.so");
  FilteredImages.push_back("libstdc++.so");
  FilteredImages.push_back("libm.so");
  FilteredImages.push_back("libm-2.16.so");
  FilteredImages.push_back("libm-2.17.so");
  FilteredImages.push_back("libc.so");
  FilteredImages.push_back("libgcc_s.so");
  FilteredImages.push_back("libselinux.so");
  FilteredImages.push_back("librt.so");
  FilteredImages.push_back("libdl.so");
  FilteredImages.push_back("libacl.so");
  FilteredImages.push_back("libattr.so");
  FilteredImages.push_back("libpthread.so");
}

/* ===================================================================== */

bool IsImageFiltered(IMG img, bool loading) {
  UINT32 img_id = IMG_Id(img);
  if(FilteredImageIds.find(img_id) != FilteredImageIds.end()) {
    //out << IMG_Name(img) << " is filtered" << endl;
    return true;
  }
  if(!loading) {
    //out << IMG_Name(img) << " is not filtered" << endl;
    return false;
  }
  string img_name = IMG_Name(img);
  for(std::vector<string>::iterator itr = FilteredImages.begin(); itr < FilteredImages.end(); ++itr) {
    if(img_name.find(*itr) != string::npos) {
      FilteredImageIds.insert(img_id);
      //out << IMG_Name(img) << " is filtered" << endl;
      return true;
    }
  }
  //out << IMG_Name(img) << " is not filtered" << endl;
  return false;
}

bool IsRoutineFiltered(RTN rtn) {
  if(RTN_Valid(rtn)) {
    return IsImageFiltered(SEC_Img(RTN_Sec(rtn)), false);
  }
  return true;
}

bool IsTraceFiltered(TRACE trace) {
  return IsRoutineFiltered(TRACE_Rtn(trace));
}

/* ===================================================================== */

void ImageLoad(IMG img, VOID *) {
  // filter out standard libraries
  // also updates filtered image ids
  //out << "Image load " << IMG_Name(img) << endl;
  if(IsImageFiltered(img, true)) {
    return;
  }
}

/* ===================================================================== */

void ImageUnload(IMG img, VOID *) {
  // delete filtering info about this image
  UINT32 img_id = IMG_Id(img);
  //out << "Image unload " << IMG_Name(img) << endl;
  FilteredImageIds.erase(img_id);
}

/* ===================================================================== */

void getValue(void *addr, Value &value) {
  // Strange bug here on some binaries, a direct call to PIN_SafeCopy(&value, (void*)memAddress, memSize) will fail
  // (stupid) patch:
  byte bytes[MAX_VALUE_SIZE_BYTES];
  switch(value.getSize()) {
  case 1:
    PIN_SafeCopy(bytes, addr, 1);
    break;
  case 2:
    PIN_SafeCopy(bytes, addr, 2);
    break;
  case 4:
    PIN_SafeCopy(bytes, addr, 4);
    break;
  case 8:
    PIN_SafeCopy(bytes, addr, 8);
    break;
  case 16:
    PIN_SafeCopy(bytes, addr, 16);
    break;
  case 32:
    PIN_SafeCopy(bytes, addr, 32);
    break;
  default:
    cerr << "UNEXPECTED SIZE: " << value.getSize() << endl;
  }
  value.setValue(bytes);
}

// Simple operations on blocks

void getBlock(Address line_addr, DataBlock &block) {
  for (int i = 0; i < BLOCK_SIZE; i++) {
    ADDRINT value = 0;
    PIN_SafeCopy(&value, (ADDRINT *)(line_addr+i), 1);
    block.setByte(i, (byte)value);
  }
}

void addBlockToMemory(Address line_addr) {
  DataBlock b;
  getBlock(line_addr, b);
  values_memory[line_addr] = b;
  //out << "Block 0x" << hex << line_addr << dec << " added to mem " << values_memory[line_addr] << endl;
}

bool isCachedBlock(int core, Address line_addr) {
  return values_cache[core].count(line_addr) == 1;
}

bool isDirtyBlock(int core, Address line_addr) {
  assert(isCachedBlock(core, line_addr));
  return values_cache[core][line_addr].isDirty();
}

void fetchBlock(int core, Address line_addr) {
  assert(isCachedBlock(core, line_addr) == false);
  if (values_memory.count(line_addr) == 0) { // Cold miss. Add block to memory
    addBlockToMemory(line_addr);
  }
  values_cache[core][line_addr] = values_memory[line_addr];
}

void refreshBlock(int core, Address line_addr) {
  assert(isCachedBlock(core, line_addr));
  assert(values_memory.count(line_addr) == 1);
  values_cache[core][line_addr].updateClean(values_memory[line_addr]);
}

void invalidateBlock(int core, Address line_addr) {
  assert(isCachedBlock(core, line_addr));
  assert(isDirtyBlock(core, line_addr) == false);
  values_cache[core].erase(line_addr);
}

void downgradeBlock(int core, Address line_addr) {
  assert(isCachedBlock(core, line_addr));
  assert(isDirtyBlock(core, line_addr));
  assert(values_memory.count(line_addr) == 1);
  values_memory[line_addr].merge(values_cache[core][line_addr]);
  values_cache[core][line_addr].resetDirtyBits();
}

void setDirtyBits(int core, Address addr, const Value &value) {
  Address line_addr = AddressUtil::makeLineAddress(addr);
  assert(isCachedBlock(core, line_addr));
  int offset = AddressUtil::getBlockOffset(addr);
  for (int i = 0; i < value.getSize(); i++) {
    assert(offset + i < BLOCK_SIZE);
    values_cache[core][line_addr].setDirtyBit(offset+i);
  }
}

void getCacheValue(int core, Address addr, Value &value) {
  Address line_addr = AddressUtil::makeLineAddress(addr);
  assert(isCachedBlock(core, line_addr));
  int offset = AddressUtil::getBlockOffset(addr);
  for (int i = 0; i < value.getSize(); i++) {
    assert(offset + i < BLOCK_SIZE);
    value.setByte(i, values_cache[core][line_addr].getByte(offset+i));
  }
}

void getMemoryValue(Address addr, Value &value) {
  Address line_addr = AddressUtil::makeLineAddress(addr);
  if (values_memory.count(line_addr) == 0) { // Cold miss. Add block to memory
    addBlockToMemory(line_addr);
  }
  int offset = AddressUtil::getBlockOffset(addr);
  for (int i = 0; i < value.getSize(); i++) {
    assert(offset + i < BLOCK_SIZE);
    value.setByte(i, values_memory[line_addr].getByte(offset+i));
  }
}

void getSCValue(Address addr, Value &value) {
  Address line_addr = AddressUtil::makeLineAddress(addr);
  assert(values_SC.count(line_addr) == 1);
  int offset = AddressUtil::getBlockOffset(addr);
  for (int i = 0; i < value.getSize(); i++) {
    assert(offset + i < BLOCK_SIZE);
    value.setByte(i, values_SC[line_addr].getByte(offset+i));
  }
}

void setCacheValue(int core, Address addr, const Value &value) {
  Address line_addr = AddressUtil::makeLineAddress(addr);
  assert(isCachedBlock(core, line_addr));
  int offset = AddressUtil::getBlockOffset(addr);
  for (int i = 0; i < value.getSize(); i++) {
    assert(offset + i < BLOCK_SIZE);
    values_cache[core][line_addr].setByte(offset+i, value.getByte(i));
  }
}

void setMemoryValue(Address addr, const Value &value) {
  Address line_addr = AddressUtil::makeLineAddress(addr);
  if (values_memory.count(line_addr) == 0) { // Cold miss. Add block to memory
    addBlockToMemory(line_addr);
  }
  int offset = AddressUtil::getBlockOffset(addr);
  for (int i = 0; i < value.getSize(); i++) {
    assert(offset + i < BLOCK_SIZE);
    values_memory[line_addr].setByte(offset+i, value.getByte(i));
  }
}

void setSCValue(Address addr, const Value &value) {
  Address line_addr = AddressUtil::makeLineAddress(addr);
  if (values_memory.count(line_addr) == 0) {
    DataBlock b;
    getBlock(line_addr, b);
    values_SC[line_addr] = b;
  }
  int offset = AddressUtil::getBlockOffset(addr);
  for (int i = 0; i < value.getSize(); i++) {
    assert(offset + i < BLOCK_SIZE);
    values_SC[line_addr].setByte(offset+i, value.getByte(i));
  }
}

void setLastWriterInfo(int core, VOID *ip, Address addr) {
  debug_info di;
  //PIN_LockClient();
  PIN_GetSourceLocation((ADDRINT)ip, &(di.column), &(di.line), &(di.filename));
  //PIN_UnlockClient();
  di.core = core;
  last_write_SC[addr] = di;
}

bool checkCacheValue(int core, VOID *ip, Address addr, const Value &value) {
  Value stored_value(value.getSize());
  getCacheValue(core, addr, stored_value);
  if (value != stored_value) {
    Address line_addr = AddressUtil::makeLineAddress(addr);
    out << "ERROR! Core " << core << " Address 0x" << hex << addr << dec << " Size: " << value.getSize() 
	<< " value " << value << " cache " << stored_value << endl;
    out << "Cache  0x" << hex << line_addr << dec << ": " << values_cache[core][line_addr] << endl;
    DataBlock b;
    getBlock(line_addr, b);
    out << "System 0x" << hex << line_addr << dec << ": " << b << endl;

    INT32 column, line;
    string filename;
    PIN_LockClient();
    PIN_GetSourceLocation((ADDRINT)ip, &column, &line, &filename);
    PIN_UnlockClient();
    out << "Error in file " << filename << " line " << line << " column " << column << endl;
    if (last_write_SC.count(addr) > 0) {
      out << "Last writer core " << last_write_SC[addr].core << " file " << last_write_SC[addr].filename << " line " << last_write_SC[addr].line << " column " << last_write_SC[addr].column << endl;
    }

    // Fix the consistency error
    if (isDirtyBlock(core, line_addr)) {
      downgradeBlock(core, line_addr);
    }
    invalidateBlock(core, line_addr);

    return 0; // Consistency error!!!
  }
  return 1;
}

void checkSCValue(Address addr, const Value &value) {
  Address line_addr = AddressUtil::makeLineAddress(addr);
  if (values_SC.count(line_addr) == 0) {
    DataBlock b;
    getBlock(line_addr, b);
    values_SC[line_addr] = b;
    return;
  }
  Value aux(value.getSize());
  getSCValue(addr, aux);
  if (value != aux) { // External write
    // This should be an error, but there are writes that the pintool cannot see (OS writes)
    // The solution is to check is the consistency problem is due to a hiden write
    // If all values in our memory system are different from the one read, its a hiden write

    // Make the write visible to SC
    setSCValue(addr, value);
    
    // Make the write visible in all RC caches and memory
    for (int i = 0; i < MAX_NUM_THREADS; i++) {
      if (values_cache[i].count(line_addr) == 1) { // Is in cache
	setCacheValue(i, addr, value);
      }
    }
    setMemoryValue(addr, value);
  }
}

void modelProtocolConsistencyRead(int core, Address addr) {
  // RC protocol
  Address line_addr = AddressUtil::makeLineAddress(addr);
  bool racy = (racy_addr_set.count(addr) > 0);
  if (racy) { // Cache by-pass
    if (isCachedBlock(core, line_addr)) {
      refreshBlock(core, line_addr);
    } else {
      fetchBlock(core, line_addr);
    }
  } else {
    if (!isCachedBlock(core, line_addr)) {
      fetchBlock(core, line_addr);
    }
  }
  assert(isCachedBlock(core, line_addr));
}

void modelProtocolConsistencyWrite(int core, Address addr, const Value &value) {
  // RC protocol
  Address line_addr = AddressUtil::makeLineAddress(addr);
  bool racy = (racy_addr_set.count(addr) > 0);
  if (racy) {
    if (isCachedBlock(core, line_addr)) {
      setCacheValue(core, addr, value);
      setDirtyBits(core, addr, value);
      downgradeBlock(core, line_addr);
    } else {
      setMemoryValue(addr, value);
    }
  } else {
    if (!isCachedBlock(core, line_addr)) {
      fetchBlock(core, line_addr);
    }
    setCacheValue(core, addr, value);
    setDirtyBits(core, addr, value);
  }
}

void modelProtocolConsistencyFullFence(int core) {
  // RC protocol
  //out << "FullFence in " << core << endl;
  for (map <Address, DataBlock>::iterator it=values_cache[core].begin(); it!=values_cache[core].end(); ++it) {
    assert(isCachedBlock(core, it->first));
    if (isDirtyBlock(core, it->first)) {
      downgradeBlock(core, it->first);
    }
  }
  values_cache[core].clear(); // invalidate all
}

void modelProtocolConsistencyLLFence(int core) {
  // RC protocol
  //out << "LLFence in " << core << endl;
  for (map <Address, DataBlock>::iterator it=values_cache[core].begin(); it!=values_cache[core].end(); ++it) {
    assert(isCachedBlock(core, it->first));
    if (isDirtyBlock(core, it->first)) {
      downgradeBlock(core, it->first);
    }
  }
  values_cache[core].clear(); // invalidate all
}

void modelProtocolConsistencySSFence(int core) {
  // RC protocol
  //out << "SSFence in " << core << endl;
  for (map <Address, DataBlock>::iterator it=values_cache[core].begin(); it!=values_cache[core].end(); ++it) {
    assert(isCachedBlock(core, it->first));
    if (isDirtyBlock(core, it->first)) {
      downgradeBlock(core, it->first);
    }
  }
}

void readValue(int core, VOID *ip, Address addr, const Value &value) {
  if (AddressUtil::isSingleBlock(addr, value.getSize()) == false) { // Multiblock
    Value v1, v2;
    Address addr2;
    value.splitInTwoBlocks(addr, v1, addr2, v2);
    readValue(core, ip, addr, v1);
    readValue(core, ip, addr2, v2);
  } else {
    modelProtocolConsistencyRead(core, addr);
    checkSCValue(addr, value);
    checkCacheValue(core, ip, addr, value);
  }
}

void writeValue(int core, VOID *ip, Address addr, const Value &value) {
  if (AddressUtil::isSingleBlock(addr, value.getSize()) == false) { // Multiblock
    Value v1, v2;
    Address addr2;
    value.splitInTwoBlocks(addr, v1, addr2, v2);
    writeValue(core, ip, addr, v1);
    writeValue(core, ip, addr2, v2);
  } else {
    modelProtocolConsistencyWrite(core, addr, value);
    setSCValue(addr, value);
  }
}

// VOID CallTrace(TRACE trace, INS ins) {
//   if (INS_IsCall(ins) && INS_IsProcedureCall(ins) && !INS_IsSyscall(ins)) {
//     if (!INS_IsDirectBranchOrCall(ins)) {
//       // Indirect call
//       PinSourceLocation* loc = PinSourceLocation::get(TRACE_Rtn(trace), INS_Address(ins));
      
//       INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(FuncCall), IARG_FAST_ANALYSIS_CALL,
// 		     IARG_THREAD_ID, IARG_BOOL, FALSE, IARG_PTR, loc,
// 		     IARG_BRANCH_TARGET_ADDR,
// 		     IARG_FUNCARG_CALLSITE_VALUE, 0, IARG_FUNCARG_CALLSITE_VALUE, 1, IARG_END);
      
//     } else if (INS_IsDirectBranchOrCall(ins)) {
//       // Direct call
//       PinSourceLocation* loc = PinSourceLocation::get(TRACE_Rtn(trace), INS_Address(ins));
      
//       ADDRINT target = INS_DirectBranchOrCallTargetAddress(ins);
      
//       INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(FuncCall), IARG_FAST_ANALYSIS_CALL,
// 		     IARG_THREAD_ID, IARG_PTR, TRUE, IARG_PTR, loc,
// 		     IARG_ADDRINT, target,
// 		     IARG_FUNCARG_CALLSITE_VALUE, 0, IARG_FUNCARG_CALLSITE_VALUE, 1, IARG_END);
      
//     }
//   } else if (INS_IsRet(ins) && !INS_IsSysret(ins)) {
//     RTN rtn = TRACE_Rtn(trace);
    
// #if defined(TARGET_LINUX) && defined(TARGET_IA32)
//     if( RTN_Valid(rtn) && RTN_Name(rtn) == "_dl_runtime_resolve") return;
//     if( RTN_Valid(rtn) && RTN_Name(rtn) == "_dl_debug_state") return;
// #endif
//     PinSourceLocation* loc = PinSourceLocation::get(rtn, INS_Address(ins));
//     INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(FuncReturn), IARG_FAST_ANALYSIS_CALL,
// 		   IARG_THREAD_ID, IARG_PTR, loc, IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);
//   }
// }

struct AddrSizePair {
	VOID * addr;
	UINT32 size;
};

LOCALVAR AddrSizePair AddrSizePairs[PIN_MAX_THREADS];

VOID MemWriteBefore(THREADID thread_id, VOID *ip, VOID *ea, UINT32 size) {
  //GetLock(&lock, thread_id+1);
  if (check_thread[thread_id] && in_sync[thread_id] == false) {
  PIN_LockClient();
    AddrSizePairs[thread_id].addr = ea;
    AddrSizePairs[thread_id].size = size;
    setLastWriterInfo(thread_id, ip, (Address)ea);
  PIN_UnlockClient();
  }
  //ReleaseLock(&lock);
}

VOID MemWrite(THREADID thread_id, VOID *ip) {
  GetLock(&lock, thread_id+1);
  if (check_thread[thread_id] && in_sync[thread_id] == false) {
    VOID *ea = AddrSizePairs[thread_id].addr;
    UINT32 size = AddrSizePairs[thread_id].size;
    Value value(size);
    getValue(ea, value);
    /* 
    out << "Write -> Id: " << thread_id << " Address: " << hex << ea << dec 
	<< ", Size: " << size
	<< ", Offset in word: " << AddressUtil::getWordOffset((Address)ea)
	<< ", Offset in block: " << AddressUtil::getBlockOffset((Address)ea)
	<< ", Value: " << value << endl;
    Address line_addr = AddressUtil::makeLineAddress((Address)ea);
    DataBlock b;
    getBlock(line_addr, b);
    out << "System 0x" << hex << line_addr << dec << ": " << b << endl;
    */
    writeValue(thread_id, ip, (Address)ea, value);
  }
  ReleaseLock(&lock);
}

VOID MemRead(THREADID thread_id, VOID *ip, VOID *ea, UINT32 size)
{
  GetLock(&lock, thread_id+1);
  if (check_thread[thread_id] && in_sync[thread_id] == false) {
    Value value(size);
    getValue(ea, value);
    /* 
    out << "Read  -> Id: " << thread_id << " Address: " << hex << ea << dec 
	<< ", Size: " << size
	<< ", Offset in word: " << AddressUtil::getWordOffset((Address)ea)
	<< ", Offset in block: " << AddressUtil::getBlockOffset((Address)ea)
	<< ", Value: " << value << endl;
    Address line_addr = AddressUtil::makeLineAddress((Address)ea);
    DataBlock b;
    getBlock(line_addr, b);
    out << "System 0x" << hex << line_addr << dec << ": " << b << endl;
    */
    readValue(thread_id, ip, (Address)ea, value);
  }
  ReleaseLock(&lock);
}

#ifdef DEBUG_WITH_GDB
static ADDRINT OnConsistencyViolationIf(THREADID thread_id, VOID *ip, VOID *ea, UINT32 size)
{
  if (check_thread[thread_id] && in_sync[thread_id] == false) {
    Value value(size);
    getValue(ea, value);
    if (AddressUtil::isSingleBlock((Address)ea, value.getSize()) == false) { // Multiblock
      Value v1, v2;
      Address ea2;
      value.splitInTwoBlocks((Address)ea, v1, ea2, v2);
      if (checkCacheValue(thread_id, ip, (Address)ea, v1)
	  || checkCacheValue(thread_id, ip, ea2, v2)) {
	return 0;
      }
    } else {
      if (checkCacheValue(thread_id, ip, (Address)ea, value)) {
	return 0;
      }
    }
    return 1;
  }
  return 0;
}

static VOID DoBreakpoint(const CONTEXT *ctxt, THREADID tid)
{
  // Construct a string that the debugger will print when it stops.  If a debugger is
  // not connected, no breakpoint is triggered and execution resumes immediately.
  //
  std::ostringstream message;
  message.str("");
  message << "Thread " << std::dec << tid << " has consistency violation.";
  PIN_ApplicationBreakpoint(ctxt, tid, FALSE, message.str());
}
#endif

VOID MemoryTrace(TRACE trace, INS ins) {
  UINT32 memOperands = INS_MemoryOperandCount(ins);

  // Iterate over each memory operand of the instruction.
  for (UINT32 memOp = 0; memOp < memOperands; memOp++) {

    if (INS_MemoryOperandIsWritten(ins, memOp)) {
      INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(MemWriteBefore),
		     IARG_THREAD_ID, 
		     IARG_INST_PTR,
		     IARG_MEMORYOP_EA, memOp,
		     IARG_UINT32, INS_MemoryOperandSize(ins, memOp),
		     IARG_END);
      if (INS_HasFallThrough(ins)) {
	INS_InsertPredicatedCall(ins, IPOINT_AFTER, AFUNPTR(MemWrite), 
				 IARG_THREAD_ID,
				 IARG_INST_PTR,
				 IARG_END);
      }
      if (INS_IsBranchOrCall(ins)) {
	INS_InsertPredicatedCall(ins, IPOINT_TAKEN_BRANCH, AFUNPTR(MemWrite), 
				 IARG_THREAD_ID, 
				 IARG_INST_PTR,
				 IARG_END);
      }
    }

    if (INS_MemoryOperandIsRead(ins, memOp)) {
      INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(MemRead), 
			       IARG_THREAD_ID,
			       IARG_INST_PTR,
			       IARG_MEMORYOP_EA, memOp,
			       IARG_UINT32, INS_MemoryOperandSize(ins, memOp),
			       IARG_END);
#ifdef DEBUG_WITH_GDB
      INS_InsertIfCall(ins, IPOINT_BEFORE, AFUNPTR(OnConsistencyViolationIf), 
      			       IARG_THREAD_ID,
      			       IARG_INST_PTR,
			       IARG_MEMORYOP_EA, memOp,
      			       IARG_UINT32, INS_MemoryOperandSize(ins, memOp),
      			       IARG_END);
      INS_InsertThenCall(ins, IPOINT_BEFORE, AFUNPTR(DoBreakpoint), 
      			 IARG_CONST_CONTEXT, IARG_THREAD_ID, IARG_END);
#endif
    }
  }
}

VOID Trace(TRACE trace, VOID *v) {
  if (IsTraceFiltered(trace)) {
    return;
  }
  for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
    for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
      if (INS_IsOriginal(ins)) {
	MemoryTrace(trace, ins);
      }
    }
  }
}

void initialization_done(THREADID thread_id) {
  GetLock(&lock, thread_id+1);
  assert(check_thread[thread_id] == false);
  check_thread[thread_id] = true;
  ReleaseLock(&lock);
}

void start_transaction(THREADID thread_id) {
  GetLock(&lock, thread_id+1);
  ReleaseLock(&lock);
}

void end_transaction(THREADID thread_id) {
  GetLock(&lock, thread_id+1);
  assert(check_thread[thread_id]);
  check_thread[thread_id] = false;
  ReleaseLock(&lock);
}

void begin_lock_acquire(THREADID thread_id, VOID *address) {
  GetLock(&lock, thread_id+1);
  //out << "BEGIN_LOCK_ACQ core " << thread_id << " LOCK " << hex << address << dec << endl;
  assert(in_sync[thread_id] == false);
  in_sync[thread_id] = true;
  num_locks++;
  ReleaseLock(&lock);
}

void end_lock_acquire(THREADID thread_id) {
  GetLock(&lock, thread_id+1);
  //out << "END_LOCK_ACQ core " << thread_id << endl;
  modelProtocolConsistencyLLFence(thread_id);
  assert(in_sync[thread_id]);
  in_sync[thread_id] = false;
  ReleaseLock(&lock);
}

void begin_lock_release(THREADID thread_id, VOID *address) {
  GetLock(&lock, thread_id+1);
  //out << "BEGIN_LOCK_REL core " << thread_id << " LOCK " << hex << address << dec << endl;
  modelProtocolConsistencySSFence(thread_id);
  assert(in_sync[thread_id] == false);
  in_sync[thread_id] = true;
  ReleaseLock(&lock);
}

void end_lock_release(THREADID thread_id) {
  GetLock(&lock, thread_id+1);
  //out << "END_LOCK_REL core " << thread_id << endl;
  assert(in_sync[thread_id]);
  in_sync[thread_id] = false;
  ReleaseLock(&lock);
}

void begin_barrier(THREADID thread_id) {
  GetLock(&lock, thread_id+1);
  modelProtocolConsistencyFullFence(thread_id); // We put it at the begin, because at the end we need to have it already, and we do not track inside
  assert(in_sync[thread_id] == false);
  in_sync[thread_id] = true;
  num_barriers++;
  ReleaseLock(&lock);
}

void end_barrier(THREADID thread_id) {
  GetLock(&lock, thread_id+1);
  assert(in_sync[thread_id]);
  in_sync[thread_id] = false;
  ReleaseLock(&lock);
}

void begin_cond_signal(THREADID thread_id) {
  GetLock(&lock, thread_id+1);
  modelProtocolConsistencySSFence(thread_id);
  assert(in_sync[thread_id] == false);
  in_sync[thread_id] = true;
  num_signals++;
  ReleaseLock(&lock);
}

void end_cond_signal(THREADID thread_id) {
  GetLock(&lock, thread_id+1);
  assert(in_sync[thread_id]);
  in_sync[thread_id] = false;
  ReleaseLock(&lock);
}

void begin_cond_wait(THREADID thread_id) {
  GetLock(&lock, thread_id+1);
  modelProtocolConsistencyLLFence(thread_id); // We put it at the begin, because at the end we need to have it already, and we do not track inside
  assert(in_sync[thread_id] == false);
  in_sync[thread_id] = true;
  ReleaseLock(&lock);
}

void end_cond_wait(THREADID thread_id) {
  GetLock(&lock, thread_id+1);
  assert(in_sync[thread_id]);
  in_sync[thread_id] = false;
  ReleaseLock(&lock);
}

void fence(THREADID thread_id, int type) {
  GetLock(&lock, thread_id+1);
  //out << "Thread " << thread_id << " executed a fence " << type << endl;
  if (type == 0 || type == 1) {
    modelProtocolConsistencyFullFence(thread_id);
  } else if (type == 2) {
    modelProtocolConsistencyLLFence(thread_id);
  } else if (type == 3) {
    modelProtocolConsistencySSFence(thread_id);
  } else {
    assert(false);
  }
  ReleaseLock(&lock);
}

void set_racy_address(THREADID thread_id, VOID *address) {
  GetLock(&lock, thread_id+1);
  //out << "Add racy address " << hex << address << dec << " by thread " << thread_id << endl;
  //racy_addr_set.insert((Address)address);
  ReleaseLock(&lock);
}

void unset_racy_address(THREADID thread_id, VOID *address) {
  GetLock(&lock, thread_id+1);
  //out << "Remove racy address " << hex << address << dec << " by thread " << thread_id << endl;
  //racy_addr_set.erase((Address)address);
  ReleaseLock(&lock);
}

VOID Routine(RTN rtn, VOID *v) {                                                                                                                      
  string name = RTN_Name(rtn);
  //out << name << endl;
  RTN_Open(rtn);
  
  if (name.find("RMS_Initialization_Done")!=string::npos){
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)initialization_done, IARG_THREAD_ID, IARG_END);
  } else if (name.find("RMS_Start_Transaction")!=string::npos){
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)start_transaction, IARG_THREAD_ID, IARG_END);
  } else if (name.find("RMS_End_Transaction")!=string::npos){
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)end_transaction, IARG_THREAD_ID, IARG_END);

  } else if (name.find("RMS_Initial_Acq")!=string::npos){
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)begin_lock_acquire, IARG_THREAD_ID, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
  } else if (name.find("RMS_Final_Acq")!=string::npos){
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)end_lock_acquire, IARG_THREAD_ID, IARG_END);
  } else if (name.find("RMS_Initial_Release")!=string::npos){
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)begin_lock_release, IARG_THREAD_ID, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
  } else if (name.find("RMS_Final_Release")!=string::npos){
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)end_lock_release, IARG_THREAD_ID, IARG_END);

  } else if (name.find("RMS_Initial_Barrier")!=string::npos){
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)begin_barrier, IARG_THREAD_ID, IARG_END);
  } else if (name.find("RMS_Final_Barrier")!=string::npos){
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)end_barrier, IARG_THREAD_ID, IARG_END);

  } else if (name.find("RMS_Initial_CondSignal")!=string::npos){
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)begin_cond_signal, IARG_THREAD_ID, IARG_END);
  } else if (name.find("RMS_Final_CondSignal")!=string::npos){
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)end_cond_signal, IARG_THREAD_ID, IARG_END);
  } else if (name.find("RMS_Initial_CondWait")!=string::npos){
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)begin_cond_wait, IARG_THREAD_ID, IARG_END);
  } else if (name.find("RMS_Final_CondWait")!=string::npos){
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)end_cond_wait, IARG_THREAD_ID, IARG_END);

  } else if (name.find("RMS_Fence")!=string::npos){
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)fence, IARG_THREAD_ID, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);

  } else if (name.find("RMS_MarkAsRacy")!=string::npos){
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)set_racy_address, IARG_THREAD_ID, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
  } else if (name.find("RMS_UnmarkAsRacy")!=string::npos){
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)unset_racy_address, IARG_THREAD_ID, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
  }

  RTN_Close(rtn);
}

// This routine is executed every time a thread is created.
VOID ThreadStart(THREADID thread_id, CONTEXT *ctxt, INT32 flags, VOID *v)
{
  GetLock(&lock, thread_id+1);
  num_threads++;
  if (num_threads > my_max_num_threads) {
    my_max_num_threads = num_threads;
  }
  check_thread[thread_id] = false;
  in_sync[thread_id] = false;
  ReleaseLock(&lock);
}

// This routine is executed every time a thread is destroyed.
VOID ThreadFini(THREADID thread_id, const CONTEXT *ctxt, INT32 code, VOID *v)
{
  GetLock(&lock, thread_id+1);
  num_threads--;
  ReleaseLock(&lock);
}

VOID Fini(INT32 code, VOID *v)
{
  out << "LOCKS: " << num_locks 
      << " BARRIERS: " << (num_barriers-1)/my_max_num_threads 
      << " SIGNALS: " << num_signals
      << endl;
  out.close();
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */
   
INT32 Usage()
{
    PIN_ERROR( "This Pintool check FSIFSD consistency\n" 
              + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{
    PIN_InitSymbols();

    if (PIN_Init(argc, argv)) return Usage();

    out.open(KnobOutputFile.Value().c_str());
    
    initialization();

    InitFilteredImages();

    // Register Analysis routines to be called when a thread begins/ends
    PIN_AddThreadStartFunction(ThreadStart, 0);
    PIN_AddThreadFiniFunction(ThreadFini, 0);

    PIN_AddFiniFunction(Fini, 0);

    IMG_AddInstrumentFunction(ImageLoad, 0);
    IMG_AddUnloadFunction(ImageUnload, 0);

    TRACE_AddInstrumentFunction(Trace, 0);

    RTN_AddInstrumentFunction(Routine, 0);

    // Never returns
    PIN_StartProgram();
    
    return 0;
}
