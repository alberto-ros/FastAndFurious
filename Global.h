/** 
 *  @file    Global.h
 *  @author  Alberto Ros (aros@um.es)
 *  
 *  @section DESCRIPTION
 *  
 *  Definitions.
 *
 */

#ifndef GLOBAL_H
#define GLOBAL_H

#include <iomanip>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <stdio.h>
#include <math.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <cassert>
#include <set>
#include <list>
#include <vector>
#include <map>

using namespace std;

#define MAX_NUM_THREADS 1024

#define BLOCK_SIZE_BITS 6 // 64 bytes
#define BLOCK_SIZE (1 << BLOCK_SIZE_BITS) // bytes

typedef unsigned char byte;
typedef unsigned long long uint64;
typedef uint64 Address;

ofstream out;

#endif //GLOBAL_H

