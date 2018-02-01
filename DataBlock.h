/** 
 *  @file    DataBlock.h
 *  @author  Alberto Ros (aros@um.es)
 *  
 *  @section DESCRIPTION
 *  
 *  A memory block with its data.
 *
 */

#ifndef DATABLOCK_H
#define DATABLOCK_H

#include "Global.h"

class DataBlock {

public:

  // Constructors
  DataBlock() {
    for (int i = 0; i < BLOCK_SIZE; i++) {
      m_dirtyBits[i] = false;
    }
    m_scopedFence = false;
    m_private = false;
    m_has_read_permission = false;
    m_has_write_permission = false;
  }

  DataBlock(byte *bytes) { 
    for (int i = 0; i < BLOCK_SIZE; i++) {
      m_dirtyBits[i] = false;
      m_bytes[i] = bytes[i];
    }
    m_scopedFence = false;
    m_private = false;
    m_has_read_permission = false;
    m_has_write_permission = false;
  }

  // Public Methods
  void setValue(byte *bytes);
  byte* getValue() const { return (byte*)&m_bytes; }
  byte getByte(int i) const { return m_bytes[i]; }
  void setByte(int i, byte b) { m_bytes[i] = b; }
  void setDirtyBit(int i) { m_dirtyBits[i] = true; }
  void resetDirtyBits();
  bool isDirtyBit(int i) const { return m_dirtyBits[i]; }
  bool isDirty() const;
  void setScopedFenceBit() { m_scopedFence = true; }
  void unsetScopedFenceBit() { m_scopedFence = false; }
  bool getScopedFenceBit() const { return m_scopedFence; }
  void setPrivateBit() { m_private = true; }
  void unsetPrivateBit() { m_private = false; }
  bool isPrivate() { return m_private; }
  void setReadPermission() { m_has_read_permission = true; }
  void unsetReadPermission() { m_has_read_permission = false; }
  bool hasReadPermission() { return m_has_read_permission; }
  void setWritePermission() { m_has_write_permission = true; }
  void unsetWritePermission() { m_has_write_permission = false; }
  bool hasWritePermission() { return m_has_write_permission; }
  void merge(const DataBlock& block);
  void updateClean(const DataBlock& block);
  
  void print(ostream& out) const;
  void output(ostream& out) const;

private:

  bool m_dirtyBits[BLOCK_SIZE];
  bool m_scopedFence;
  bool m_private;
  bool m_has_read_permission;
  bool m_has_write_permission;
  byte m_bytes[BLOCK_SIZE];
};

// Output operator declaration
ostream& operator<<(ostream& out, const DataBlock& obj);

// Comparison operator declaration
bool operator==(const DataBlock& obj1, const DataBlock& obj2);
bool operator!=(const DataBlock& obj1, const DataBlock& obj2);

// ******************* Definitions *******************

// Output operator definition
inline
ostream& operator<<(ostream& out, const DataBlock& obj)
{
  obj.print(out);
  out << flush;
  return out;
}

inline
bool operator==(const DataBlock& obj1, const DataBlock& obj2) {
  for (int i = 0; i < BLOCK_SIZE; i++) {
    if (obj1.getByte(i) != obj2.getByte(i)) return false;
  }
  return true;
}

inline
bool operator!=(const DataBlock& obj1, const DataBlock& obj2) {
  return !(obj1 == obj2);
}

inline
void DataBlock::setValue(byte *bytes) {
  for (int i = 0; i < BLOCK_SIZE; i++) {
    m_bytes[i] = bytes[i];
  }
}

inline
void DataBlock::resetDirtyBits() {
  for (int i = 0; i < BLOCK_SIZE; i++) {
    m_dirtyBits[i] = false;
  }
}

inline
bool DataBlock::isDirty() const {
  for (int i = 0; i < BLOCK_SIZE; i++) {
    if (m_dirtyBits[i]) return true;
  }
  return false;
}

inline
void DataBlock::merge(const DataBlock& block) {
  for (int i = 0; i < BLOCK_SIZE; i++) {
    if (block.isDirtyBit(i)) {
      m_bytes[i] = block.getByte(i);
    }
  }
}

inline
void DataBlock::updateClean(const DataBlock& block) {
  for (int i = 0; i < BLOCK_SIZE; i++) {
    if (!m_dirtyBits[i]) {
      m_bytes[i] = block.getByte(i);
    }
  }
}

inline
void DataBlock::print(ostream& out) const {
  for (int i = 0; i < BLOCK_SIZE; i++) {
    if (m_dirtyBits[i]) out << "*"; 
    out << hex << ((unsigned)m_bytes[i]) << dec << " ";
  }
}

#endif //DATABLOCK_H
