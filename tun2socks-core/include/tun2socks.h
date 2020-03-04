#pragma once

#ifdef USE_DLL
#ifdef COMPILE_DLL	
#define DECLSPEC extern "C" __declspec(dllexport)
#else
#define DECLSPEC extern "C" __declspec(dllimport)
#endif
#else
#define DECLSPEC extern "C"
#endif

#include <cstdint>
#include <cstddef> // for std::size_t

#include "socks5_auth.h"

#ifdef __WIN32__
#include <Windows.h>

typedef HANDLE TUNHANDLE;

#define TUN_INVALID_HANDLE INVALID_HANDLE_VALUE;

#endif

#ifdef __LINUX__
typedef int HANDLE;
typedef HANDLE TUNHANDLE;
#define INVALID_HANDLE_VALUE (-1)
#define TUN_INVALID_HANDLE INVALID_HANDLE_VALUE
#endif

#define MAX_LEN 256

#ifndef NULL
#define NULL (0)
#endif

using size_t = std::size_t;

typedef uint32_t IPADDR;

typedef struct _TUNAdapter {
	TUNHANDLE hd;
#ifdef __WIN32__
	char dev_id[MAX_LEN + 1];
	DWORD index;
#endif
#ifdef __LINUX__
    int ctrl_socket;
    int flags;
#endif
	char dev_name[MAX_LEN + 1];
	IPADDR ip;
	IPADDR mask;
	uint32_t network;
} TUNAdapter, *PTUNAdapter;

typedef struct _TUN2SOCKSConfig {
	PTUNAdapter adapter;
	char socks5_address[256];
	size_t socks5_address_length;
	uint16_t socks5_port;
	PBaseAuth socks5_auth;
	uint32_t udp_timeout;
} TUN2SOCKSConfig, *PTUN2SOCKSConfig;

#ifdef __WIN32__
DECLSPEC
size_t get_tuns(TUNAdapter*, size_t);
#endif

DECLSPEC
TUNAdapter* open_tun(TUNAdapter* = NULL);

DECLSPEC
void delete_tun(TUNAdapter*);

DECLSPEC
PTUN2SOCKSConfig make_config_with_socks5_no_auth(
	const TUNAdapter*,
	const char*, size_t,
	uint16_t,
	uint32_t,
	const SOCKS5NoAuth*
);

DECLSPEC
PTUN2SOCKSConfig make_config_with_socks5_password_auth(
	const TUNAdapter*,
	const char*, size_t,
	uint16_t,
	uint32_t,
	const SOCKS5UsernamePassword*
);

DECLSPEC
void delete_config(PTUN2SOCKSConfig);

DECLSPEC
void tun2socks_start(const TUN2SOCKSConfig*);