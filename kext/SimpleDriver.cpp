/*
	File:			SimpleDriver.cpp
	
	Description:	This file shows how to implement a basic I/O Kit driver kernel extension (KEXT).

	Copyright:		Copyright © 2001-2008 Apple Inc. All rights reserved.
	Copyright:		Copyright © 2016 xerub
*/


#include <IOKit/IOLib.h>
#include "SimpleDriver.h"

#define super IOService

// Even though we are defining the convenience macro super for the superclass, you must use the actual class name
// in the OS*MetaClass macros. Note that the class name is different when supporting Mac OS X 10.4.

OSDefineMetaClassAndStructors(XerubDriver, IOService)

bool
XerubDriver::start(IOService *provider)
{
	bool success;

	IOLog("%s[%p]::%s(%p)\n", getName(), this, __FUNCTION__, provider);

	success = super::start(provider);

	if (success) {
		// Publish ourselves so clients can find us
		registerService();
	}

	return success;
}

IOReturn
XerubDriver::testMe(uint32_t *demo)
{
	IOLog("%s[%p]::%s()\n", getName(), this, __FUNCTION__);

	*demo = 0xdeaf0000;

	return kIOReturnSuccess;
}
