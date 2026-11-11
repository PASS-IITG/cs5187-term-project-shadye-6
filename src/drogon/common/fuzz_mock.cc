#include "fuzz_mock.h"
#include <trantor/utils/Logger.h>
#include <cstdlib>

namespace fz {

trantor::EventLoop *loop() {
    // Return the thread's event loop (Drogon initializes one before main) or construct if none.
    static trantor::EventLoop *l = trantor::EventLoop::getEventLoopOfCurrentThread();
    if (!l) l = new trantor::EventLoop();
    return l;
}

const trantor::TcpConnectionPtr &conn() {
    static trantor::TcpConnectionPtr c = std::make_shared<MockTcpConnection>();
    return c;
}

void init() {
    static bool done = false;
    if (done) return;
    done = true;
    if (!std::getenv("FUZZ_LOG"))
        trantor::Logger::setLogLevel(trantor::Logger::kFatal);
    loop();
    conn();
}

}  // namespace fz
