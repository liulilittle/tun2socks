/*
	Lazymio 2/10/2019
	Port lwip to Windows.
	The codes below are under GPLv3 License.
*/
#ifndef LWIP_ARCH_CC_H
#define LWIP_ARCH_CC_H

/*
	Just for memset.
*/
#include <string.h>

/*
	We didn't have unistd.h indeed.
*/
#define LWIP_NO_UNISTD_H 1

/*
	Using default values is okay.
*/

#define PACK_STRUCT_USE_INCLUDES 1

#endif
