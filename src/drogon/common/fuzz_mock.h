/* Headless plumbing so Drogon's connection-bound parsers run on the fuzzing thread.
 *
 * Drogon's HttpRequestParser / HttpResponseParser / WebSocketConnectionImpl are constructed from a
 * trantor::TcpConnectionPtr and keep a weak_ptr to it; HttpRequestImpl stores the connection's
 * EventLoop and asserts isInLoopThread() in appendToBody()/reset(). We therefore need (1) a real
 * trantor::EventLoop *constructed on this thread* (trantor binds a loop to its constructing thread,
 * and isInLoopThread() is then true without ever running the loop), and (2) a TcpConnection whose
 * every I/O method is a no-op/stub. MockTcpConnection implements the full virtual interface; send()
 * swallows bytes (the only path a parser actually calls, on `Expect: 100-continue`).
 *
 * This is the Drogon analogue of raylib's fz_init(FZ_GL): one process-wide headless context that
 * every harness shares, created once. */
#ifndef FUZZ_MOCK_H
#define FUZZ_MOCK_H
#include <trantor/net/TcpConnection.h>
#include <trantor/net/EventLoop.h>
#include <memory>

namespace fz {

/// Process-wide EventLoop bound to the fuzzing thread (never run; only used for isInLoopThread()).
trantor::EventLoop *loop();

/// A throwaway connection for constructing a parser. All effects are discarded.
class MockTcpConnection final : public trantor::TcpConnection
{
  public:
    MockTcpConnection() = default;
    ~MockTcpConnection() override = default;

    // ---- sends: swallow everything ----
    void send(const char *, size_t) override {}
    void send(const void *, size_t) override {}
    void send(const std::string &) override {}
    void send(std::string &&) override {}
    void send(const trantor::MsgBuffer &) override {}
    void send(trantor::MsgBuffer &&) override {}
    void send(const std::shared_ptr<std::string> &) override {}
    void send(const std::shared_ptr<trantor::MsgBuffer> &) override {}
    void sendFile(const char *, long long, long long) override {}
    void sendFile(const wchar_t *, long long, long long) override {}
    void sendStream(std::function<std::size_t(char *, std::size_t)>) override {}
    trantor::AsyncStreamPtr sendAsyncStream(bool) override { return nullptr; }

    // ---- addresses / state ----
    const trantor::InetAddress &localAddr() const override { return addr_; }
    const trantor::InetAddress &peerAddr() const override { return addr_; }
    bool connected() const override { return connected_; }
    bool disconnected() const override { return !connected_; }
    trantor::MsgBuffer *getRecvBuffer() override { return &recv_; }

    void setHighWaterMarkCallback(const trantor::HighWaterMarkCallback &, size_t) override {}
    void setTcpNoDelay(bool) override {}
    void shutdown() override { connected_ = false; }
    void forceClose() override { connected_ = false; }
    trantor::EventLoop *getLoop() override { return loop(); }
    std::string applicationProtocol() const override { return {}; }
    void keepAlive() override { keepAlive_ = true; }
    bool isKeepAlive() override { return keepAlive_; }
    size_t bytesSent() const override { return 0; }
    size_t bytesReceived() const override { return 0; }

    // ---- TLS (null) ----
    bool isSSLConnection() const override { return false; }
    trantor::CertificatePtr peerCertificate() const override { return nullptr; }
    trantor::CertificatePtr localCertificate() const override { return nullptr; }
    std::string sniName() const override { return {}; }
    void startEncryption(trantor::TLSPolicyPtr, bool,
                         std::function<void(const trantor::TcpConnectionPtr &)>) override {}

    // ---- internal APIs ----
    void connectEstablished() override {}
    void connectDestroyed() override {}
    void enableKickingOff(size_t, const std::shared_ptr<trantor::TimingWheel> &) override {}
    void forwardToTLSBuffer(trantor::MsgBuffer *) override {}

  private:
    trantor::InetAddress addr_;
    trantor::MsgBuffer recv_;
    bool connected_{true};
    bool keepAlive_{false};
};

/// Shared mock connection (one is enough: parsers only read its loop and discard sends).
const trantor::TcpConnectionPtr &conn();

/// One-time headless init: builds the loop + mock conn, silences trantor logging unless FUZZ_LOG.
void init();

}  // namespace fz
#endif
