#ifndef CONTEXT_H
#define CONTEXT_H

#include <memory>
#include <optional>

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
    virtual auto private_key() const -> std::optional<std::shared_ptr<lbcrypto::LWEPrivateKeyImpl>> = 0;
    virtual auto zero() -> std::shared_ptr<lbcrypto::LWECiphertextImpl const> const = 0;
    virtual auto one() -> std::shared_ptr<lbcrypto::LWECiphertextImpl const> const = 0;

    virtual auto decrypt(std::shared_ptr<lbcrypto::LWECiphertextImpl const> const& bit) const -> bool = 0;

    struct Impl;

    static auto generate() -> std::unique_ptr<Context>;
};
} // namespace cryptvm

#endif // CONTEXT_H
