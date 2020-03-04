#include <time.h>
#include <Windows.h>
#include <hash_set>
#include <mutex>

#include "lwip/sys.h"

static LARGE_INTEGER freq, sys_start_time;
static std::mutex sys_arch_pcb_sets_syncobj;
static stdext::hash_set<void*> sys_arch_pcb_sets;

void sys_init(void) {
	QueryPerformanceFrequency(&freq);
	QueryPerformanceCounter(&sys_start_time);
}

static LONGLONG
sys_get_ms_longlong(void)
{
	LONGLONG ret;
	LARGE_INTEGER now;
	if (freq.QuadPart == 0) {
		sys_init();
	}
	QueryPerformanceCounter(&now);
	ret = now.QuadPart - sys_start_time.QuadPart;
	return (u32_t)(((ret) * 1000) / freq.QuadPart);
}

u32_t
sys_jiffies(void)
{
	return (u32_t)sys_get_ms_longlong();
}

u32_t
sys_now(void)
{
	return (u32_t)sys_get_ms_longlong();
}

int sys_arch_pcb_watch(void* pcb)
{
	if (NULL == pcb) {
		return 0;
	}

	int rc = 0;
	sys_arch_pcb_sets_syncobj.lock();
	{
		rc = sys_arch_pcb_sets.insert(pcb).second ? 1 : 0;
	}
	sys_arch_pcb_sets_syncobj.unlock();

	return rc;
}

int sys_arch_pcb_is_watch(void* pcb)
{
	if (NULL == pcb) {
		return 0;
	}

	int rc = 0;
	sys_arch_pcb_sets_syncobj.lock();
	{
		rc = sys_arch_pcb_sets.find(pcb) != sys_arch_pcb_sets.end() ? 1 : 0;
	}
	sys_arch_pcb_sets_syncobj.unlock();

	return rc;
}

int sys_arch_pcb_unwatch(void* pcb)
{
	if (NULL == pcb) {
		return 0;
	}

	int rc = 0;
	sys_arch_pcb_sets_syncobj.lock();
	{
		auto tail = sys_arch_pcb_sets.find(pcb);
		if (tail != sys_arch_pcb_sets.end()) {
			rc = 1;
			sys_arch_pcb_sets.erase(tail);
		}
	}
	sys_arch_pcb_sets_syncobj.unlock();

	return rc;
}
