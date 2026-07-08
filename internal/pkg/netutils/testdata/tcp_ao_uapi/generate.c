// Copyright (C) 2026 The GoBGP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Generate whole-record TCP-AO ABI fixtures from the installed Linux UAPI.
// This file is not compiled by Go tests; see README.md for regeneration.

#include <arpa/inet.h>
#include <linux/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "TCP-AO fixtures must be generated on a supported little-endian host"
#endif

_Static_assert(sizeof(struct __kernel_sockaddr_storage) == 128,
               "unexpected sockaddr storage size");
_Static_assert(sizeof(struct tcp_ao_add) == 288,
               "unexpected tcp_ao_add size");
_Static_assert(sizeof(struct tcp_ao_del) == 144,
               "unexpected tcp_ao_del size");
_Static_assert(sizeof(struct tcp_ao_info_opt) == 48,
               "unexpected tcp_ao_info_opt size");

static void fail(const char *operation)
{
	perror(operation);
	exit(EXIT_FAILURE);
}

static void set_ipv4(struct __kernel_sockaddr_storage *storage,
		     const char *address)
{
	struct sockaddr_in value = {
		.sin_family = AF_INET,
	};

	if (inet_pton(AF_INET, address, &value.sin_addr) != 1)
		fail("inet_pton(AF_INET)");
	memcpy(storage, &value, sizeof(value));
}

static void set_ipv6(struct __kernel_sockaddr_storage *storage,
		     const char *address)
{
	struct sockaddr_in6 value = {
		.sin6_family = AF_INET6,
	};

	if (inet_pton(AF_INET6, address, &value.sin6_addr) != 1)
		fail("inet_pton(AF_INET6)");
	memcpy(storage, &value, sizeof(value));
}

static void emit(const char *name, const void *record, size_t size)
{
	const unsigned char *bytes = record;
	FILE *output = fopen(name, "w");

	if (output == NULL)
		fail(name);
	for (size_t i = 0; i < size; i++) {
		if (fprintf(output, "%02x", bytes[i]) < 0)
			fail(name);
		if ((i + 1) % 32 == 0 || i + 1 == size) {
			if (fputc('\n', output) == EOF)
				fail(name);
		}
	}
	if (fclose(output) != 0)
		fail(name);
}

int main(int argc, char **argv)
{
	struct tcp_ao_add add_ipv4 = {0};
	struct tcp_ao_add add_ipv6 = {0};
	struct tcp_ao_del del_ipv4 = {0};
	struct tcp_ao_info_opt info = {0};
	const char hmac_key[] = "secret";
	const char cmac_key[] = "0123456789abcdef";

	if (argc != 2) {
		fprintf(stderr, "usage: %s OUTPUT_DIRECTORY\n", argv[0]);
		return EXIT_FAILURE;
	}
	if (chdir(argv[1]) != 0)
		fail(argv[1]);

	set_ipv4(&add_ipv4.addr, "192.0.2.1");
	memcpy(add_ipv4.alg_name, "hmac(sha1)", sizeof("hmac(sha1)") - 1);
	add_ipv4.ifindex = 0x01020304;
	add_ipv4.set_current = 1;
	add_ipv4.set_rnext = 1;
	add_ipv4.prefix = 32;
	add_ipv4.sndid = 7;
	add_ipv4.rcvid = 9;
	add_ipv4.maclen = 12;
	add_ipv4.keyflags = TCP_AO_KEYF_IFINDEX | TCP_AO_KEYF_EXCLUDE_OPT;
	add_ipv4.keylen = sizeof(hmac_key) - 1;
	memcpy(add_ipv4.key, hmac_key, sizeof(hmac_key) - 1);

	set_ipv6(&add_ipv6.addr, "2001:db8:1::");
	memcpy(add_ipv6.alg_name, "cmac(aes128)", sizeof("cmac(aes128)") - 1);
	add_ipv6.prefix = 64;
	add_ipv6.sndid = 1;
	add_ipv6.rcvid = 2;
	add_ipv6.maclen = 12;
	add_ipv6.keylen = sizeof(cmac_key) - 1;
	memcpy(add_ipv6.key, cmac_key, sizeof(cmac_key) - 1);

	set_ipv4(&del_ipv4.addr, "198.51.100.0");
	del_ipv4.ifindex = 42;
	del_ipv4.prefix = 24;
	del_ipv4.sndid = 7;
	del_ipv4.rcvid = 9;
	del_ipv4.keyflags = TCP_AO_KEYF_IFINDEX;

	info.set_current = 1;
	info.set_rnext = 1;
	info.current_key = 7;
	info.rnext = 23;

	emit("add_ipv4.hex", &add_ipv4, sizeof(add_ipv4));
	emit("add_ipv6.hex", &add_ipv6, sizeof(add_ipv6));
	emit("del_ipv4.hex", &del_ipv4, sizeof(del_ipv4));
	emit("info.hex", &info, sizeof(info));
	return EXIT_SUCCESS;
}
