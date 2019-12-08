#ifndef CONTEXT_H
#define CONTEXT_H

#include <memory>

namespace lbcrypto
{
class BinFHEContext;
class LWECiphertextImpl;
class LWEPrivateKeyImpl;
} // namespace lbcrypto

namespace cryptvm
{
struct Context
{
    virtual ~Context() = default;
    virtual auto ctx() const -> lbcrypto::BinFHEContext& = 0;
    virtual auto zero() const -> std::shared_ptr<lbcrypto::LWECiphertextImpl const> const = 0;
    virtual auto one() const -> std::shared_ptr<lbcrypto::LWECiphertextImpl const> const = 0;

    struct Impl;

    static auto generate() -> std::pair<std::unique_ptr<Context>, std::shared_ptr<lbcrypto::LWEPrivateKeyImpl>>;
};
} // namespace cryptvm

#endif // CONTEXT_H
