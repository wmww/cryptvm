#ifndef NUMBER_H
#define NUMBER_H

#include <memory>

namespace lbcrypto
{
class BinFHEContext;
class LWEPrivateKeyImpl;
class LWECiphertextImpl;
} // namespace lbcrypto

namespace cryptvm
{
struct Context;

struct Number
{
    virtual ~Number() = default;
    virtual auto bits() const -> size_t = 0;
    virtual auto operator[](int i) const -> std::shared_ptr<lbcrypto::LWECiphertextImpl> = 0;
    virtual auto decrypt(std::shared_ptr<lbcrypto::LWEPrivateKeyImpl> const& key) -> unsigned = 0;

    virtual void increment() = 0;

    struct Impl;

    static auto from_plaintext(std::shared_ptr<Context> const& ctx,
                               std::shared_ptr<lbcrypto::LWEPrivateKeyImpl> const& key,
                               size_t bits,
                               unsigned value) -> std::unique_ptr<Number>;

    static auto zero(std::shared_ptr<Context> const& ctx, size_t bits) -> std::unique_ptr<Number>;
};
} // namespace cryptvm

#endif // NUMBER_H
