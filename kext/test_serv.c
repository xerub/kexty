#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <IOKit/IOKitLib.h>

int
main(void)
{
    kern_return_t ret;
    io_connect_t conn = 0;
    io_service_t dev = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("XerubDriver"));
    if (dev) {
        ret = IOServiceOpen(dev, mach_task_self(), 0, &conn);
        if (ret == kIOReturnSuccess) {
            uint64_t scalarO_64 = 0;
            uint32_t outputCount = 1;
            ret = IOConnectCallScalarMethod(conn, 0, NULL, 0, &scalarO_64, &outputCount);
            if (ret == 0) {
                printf("scalarO_64 = %x\n", (uint32_t)scalarO_64);
            }
            IOServiceClose(conn);
        }
        IOObjectRelease(dev);
    }
    return 0;
}
