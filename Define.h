#ifndef SOCKS_SERVER_DEFINE_H
#define SOCKS_SERVER_DEFINE_H

#include <string>

struct SOCKS5_REQ
{
    char	version;
    char	command;
    char	reserved;
    char	atyp;
    union
    {
        unsigned long 	ip;
        struct
        {
            char	len;
            char	domain[1];
        };
    };
    unsigned short	port;
};


#ifdef DEBUG
#define LogDebug(fmt, ...) do {																				\
char log_buffer[4096] = { 0 };																	            \
char* name = strrchr(__FILE__, '\\');																		\
name = (name == nullptr) ? __FILE__ : name + 1;													            \
sprintf_s(log_buffer, 4096 -1, "[%s:%d] " fmt "\n", name, __LINE__, ##__VA_ARGS__);			                \
OutputDebugStringA(log_buffer);																				\
} while (0)

#else
#define LogDebug(fmt, ...) do {} while (0)
#endif

#endif //SOCKS_SERVER_DEFINE_H
