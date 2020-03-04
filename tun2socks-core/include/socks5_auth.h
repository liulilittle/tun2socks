#pragma once

#include <cstdint>

using size_t = std::size_t;

enum SOCKS5METHOD :uint8_t {
	NO_AUTH = 0,
	USERNAME_PASSWORD = 2
};

#define SOCKS5AUTH_BASE_MEMBER \
	SOCKS5METHOD method;

typedef struct _SOCKS5NoAuth {
	SOCKS5AUTH_BASE_MEMBER
} BaseAuth, *PBaseAuth, SOCKS5NoAuth, *PSOCKS5NoAuth;

typedef struct _SOCKS5UsernamePassword {
	SOCKS5AUTH_BASE_MEMBER
	char username[256];
	size_t username_length;
	char password[256];
	size_t password_length;
} SOCKS5UsernamePassword, *PSOCKS5UsernamePassword;