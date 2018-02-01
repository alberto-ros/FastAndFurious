/** 
 *  @file    Value.h
 *  @author  Alberto Ros (aros@um.es)
 *  
 *  @section DESCRIPTION
 *  
 *  A value to be read or stored in a data block.
 *
 */

#ifndef VALUE_H
#define VALUE_H

#include "AddressUtil.h"

# define MAX_VALUE_SIZE_BYTES 32

class Value {
public:
  // Constructors
  Value() { m_size = 0; }
  Value(int size) { m_size = size; }
  Value(int size, byte *bytes) { 
    m_size = size; 
    for (int i = 0; i < size; i++) {
      m_bytes[i] = bytes[i];
    }
  }

  // Public Methods
  void setValue(int size, byte *bytes);
  void setValue(byte *bytes);
  int getSize() const { return m_size; }
  void setSize(int size) { m_size = size; }
  byte getByte(int i) const { return m_bytes[i]; }
  void setByte(int i, byte b) { m_bytes[i] = b; }
  void splitInTwoBlocks(Address addr, Value &v1, Address &addr2, Value &v2) const;

  void print(ostream& out) const;
  void output(ostream& out) const;

private:
  int m_size;
  byte m_bytes[MAX_VALUE_SIZE_BYTES];
};

// Output operator declaration
ostream& operator<<(ostream& out, const Value& obj);

// Comparison operator declaration
bool operator==(const Value& obj1, const Value& obj2);
bool operator!=(const Value& obj1, const Value& obj2);

// ******************* Definitions *******************

// Output operator definition
inline
ostream& operator<<(ostream& out, const Value& obj)
{
  obj.print(out);
  out << flush;
  return out;
}

inline
bool operator==(const Value& obj1, const Value& obj2) {
  if (obj1.getSize() != obj2.getSize()) return false;
  for (int i = 0; i < obj1.getSize(); i++) {
    if (obj1.getByte(i) != obj2.getByte(i)) return false;
  }
  return true;
}

inline
bool operator!=(const Value& obj1, const Value& obj2) {
  return !(obj1 == obj2);
}

inline
void Value::setValue(int size, byte *bytes) {
  m_size = size; 
  for (int i = 0; i < size; i++) {
    m_bytes[i] = bytes[i];
  }
}

inline
void Value::setValue(byte *bytes) {
  for (int i = 0; i < m_size; i++) {
    m_bytes[i] = bytes[i];
  }
}

inline
void Value::splitInTwoBlocks(Address addr, Value &v1, Address &addr2, Value &v2) const {
  // First value
  Address addr_end = addr + m_size - 1;
  int size1 = AddressUtil::makeLineAddress(addr_end) - addr;
  v1.setSize(size1);
  for (int i = 0; i < size1; i++) {
    v1.setByte(i, m_bytes[i]);
  }

  // Second value
  addr2 = AddressUtil::makeLineAddress(addr_end);
  int size2 = addr_end + 1 - addr2;
  v2.setSize(size2);
  for (int i = 0; i < size2; i++) {
    v2.setByte(i, m_bytes[size1 + i]);
  }
}

inline
void Value::print(ostream& out) const {
  out << "0x" << hex;
  for (int i = m_size - 1; i >= 0; i--) { // little endian
    out << ((unsigned)m_bytes[i]);
  }
  out << dec;
}

#endif //VALUE_H
