#include <iostream>

#include "SocksServer.h"

#include <boost/make_shared.hpp>

int main() {
    auto server = boost::make_shared<SocksServer>();
    server->Start("127.0.0.1", 9981);

    return 0;
}
