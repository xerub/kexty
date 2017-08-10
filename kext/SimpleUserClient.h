/*
	File:			SimpleUserClient.h
	
	Description:	This file shows how to implement a simple I/O Kit user client that is Rosetta-aware.

	Copyright:		Copyright © 2001-2008 Apple Inc. All rights reserved.
*/


#include <IOKit/IOService.h>
#include <IOKit/IOUserClient.h>
#include "SimpleDriver.h"

class XerubUserClient : public IOUserClient {
	OSDeclareDefaultStructors(XerubUserClient)

protected:
	XerubDriver *fProvider;
	task_t fTask;
	bool fCrossEndian;
	static const IOExternalMethodDispatch sMethods[kNumberOfMethods];

public:
	// IOUserClient methods
	virtual bool start(IOService *provider);

	virtual bool initWithTask(task_t owningTask, void *securityToken, UInt32 type, OSDictionary *properties);

protected:
	// KPI for supporting access from both 32-bit and 64-bit user processes beginning with Mac OS X 10.5.
	virtual IOReturn externalMethod(uint32_t selector, IOExternalMethodArguments *arguments, IOExternalMethodDispatch *dispatch, OSObject *target, void *reference);

	// SimpleUserClient methods
	static IOReturn sTestMe(XerubDriver *target, void *reference, IOExternalMethodArguments *arguments);
};
