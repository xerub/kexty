/*
	File:			UserKernelShared.h

	Description:	Definitions shared between SimpleUserClient (kernel) and SimpleUserClientTool (userland).

	Copyright:		Copyright © 2001-2008 Apple Inc. All rights reserved.
*/

#define kXerubDriverClassName		"XerubDriver"

// Data structure passed between the tool and the user client. This structure and its fields need to have
// the same size and alignment between the user client, 32-bit processes, and 64-bit processes.
// To avoid invisible compiler padding, align fields on 64-bit boundaries when possible
// and make the whole structure's size a multiple of 64 bits.

// User client method dispatch selectors.
enum {
    kMyTestMethod,
    kNumberOfMethods // Must be last
};
