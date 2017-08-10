/*
	File:			SimpleUserClient.cpp
	
	Description:	This file shows how to implement a simple I/O Kit user client that is Rosetta-aware.

	Copyright:		Copyright © 2001-2008 Apple Inc. All rights reserved.
	Copyright:		Copyright © 2016 xerub
*/


#include <IOKit/IOLib.h>
#include <IOKit/IOKitKeys.h>
#include <libkern/OSByteOrder.h>
#include "SimpleUserClient.h"


#define super IOUserClient

// Even though we are defining the convenience macro super for the superclass, you must use the actual class name
// in the OS*MetaClass macros.

OSDefineMetaClassAndStructors(XerubUserClient, IOUserClient)

// This is the technique which supports both 32-bit and 64-bit user processes starting with Mac OS X 10.5.
//
// User client method dispatch table.
//
// The user client mechanism is designed to allow calls from a user process to be dispatched to
// any IOService-based object in the kernel. Almost always this mechanism is used to dispatch calls to
// either member functions of the user client itself or of the user client's provider. The provider is
// the driver which the user client is connecting to the user process.
//
// It is recommended that calls be dispatched to the user client and not directly to the provider driver.
// This allows the user client to perform error checking on the parameters before passing them to the driver.
// It also allows the user client to do any endian-swapping of parameters in the cross-endian case.

const IOExternalMethodDispatch XerubUserClient::sMethods[kNumberOfMethods] = {
	{   // kMyTestMethod
		(IOExternalMethodAction) &XerubUserClient::sTestMe,	// Method pointer.
		0,												// No scalar input values.
		0,												// No struct input value.
		1,												// One scalar output value.
		0												// No struct output value.
	}
};

IOReturn
XerubUserClient::externalMethod(uint32_t selector, IOExternalMethodArguments *arguments, IOExternalMethodDispatch *dispatch, OSObject *target, void *reference)
{
	IOLog("%s[%p]::%s(%d, %p, %p, %p, %p)\n", getName(), this, __FUNCTION__, selector, arguments, dispatch, target, reference);

	if (selector < (uint32_t) kNumberOfMethods) {
		dispatch = (IOExternalMethodDispatch *) &sMethods[selector];
		if (!target) {
			target = fProvider;
		}
	}
	return super::externalMethod(selector, arguments, dispatch, target, reference);
}

// There are two forms of IOUserClient::initWithTask, the second of which accepts an additional OSDictionary* parameter.
// If your user client needs to modify its behavior when it's being used by a process running using Rosetta,
// you need to implement the form of initWithTask with this additional parameter.
//
// initWithTask is called as a result of the user process calling IOServiceOpen.
bool
XerubUserClient::initWithTask(task_t owningTask, void *securityToken, UInt32 type, OSDictionary *properties)
{
	bool success;

	success = super::initWithTask(owningTask, securityToken, type, properties);

	// This IOLog must follow super::initWithTask because getName relies on the superclass initialization.
	IOLog("%s[%p]::%s(%p, %p, %u, %p)\n", getName(), this, __FUNCTION__, owningTask, securityToken, (unsigned)type, properties);

	if (success) {
	}

	fTask = owningTask;
	fProvider = NULL;

	return success;
}

// start is called after initWithTask as a result of the user process calling IOServiceOpen.
bool
XerubUserClient::start(IOService *provider)
{
	bool success;

	IOLog("%s[%p]::%s(%p)\n", getName(), this, __FUNCTION__, provider);

	// Verify that this user client is being started with a provider that it knows
	// how to communicate with.
	fProvider = OSDynamicCast(XerubDriver, provider);
	success = (fProvider != NULL);

	if (success) {
		// It's important not to call super::start if some previous condition
		// (like an invalid provider) would cause this function to return false.
		// I/O Kit won't call stop on an object if its start function returned false.
		success = super::start(provider);
	}

	return success;
}

IOReturn
XerubUserClient::sTestMe(XerubDriver *target, void *reference, IOExternalMethodArguments *arguments)
{
	return target->testMe((uint32_t *)&arguments->scalarOutput[0]);
}
