/** 
 *  @file    AddressUtil.h
 *  @author  Alberto Ros (aros@um.es)
 *  
 *  @section DESCRIPTION
 *  
 *  Operations for the type Address.
 *
 */

#ifndef ADDRESSUTIL_H
#define ADDRESSUTIL_H

#include "Global.h"

const int ADDRESS_WIDTH = 64; // address width in bytes

class AddressUtil {

public:

  // Public Methods
  static Address bitSelect(Address addr, int small, int big); 
  static Address maskLowOrderBits(Address addr, int number); 
  static Address getBlockOffset(Address addr) { return bitSelect(addr, 0, BLOCK_SIZE_BITS-1); };
  static Address makeLineAddress(Address addr) { return maskLowOrderBits(addr, BLOCK_SIZE_BITS); }
  static bool isSingleBlock(Address addr, int size) { return (makeLineAddress(addr) == makeLineAddress(addr+size-1)); }

private:

};

inline
Address AddressUtil::bitSelect(Address addr, int small, int big) // rips bits inclusive
{
  Address mask;
  assert(big >= small);

  if (big >= ADDRESS_WIDTH - 1) {
    return (addr >> small);
  } else {
    mask = ~((Address)~0 << (big + 1));
    // FIXME - this is slow to manipulate a 64-bit number using 32-bits
    Address partial = (addr & mask); 
    return (partial >> small);
  }
}

inline
Address AddressUtil::maskLowOrderBits(Address addr, int number) 
{
  Address mask;
  
  if (number >= ADDRESS_WIDTH - 1) {
    mask = ~0;
  } else {
    mask = (Address)~0 << number;
  }
  return (addr & mask);
}

#endif //ADDRESSUTIL_H

