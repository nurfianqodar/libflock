#include "util.h"
#include <time.h>

uint64_t time_now(void)
{
	return (uint64_t)time(NULL);
}


