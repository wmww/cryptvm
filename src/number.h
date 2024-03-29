#ifndef NUMBER_H
#define NUMBER_H

#include <memory>
#include <vector>

namespace lbcrypto
{
class BinFHEContext;
class LWEPrivateKeyImpl;
class LWECiphertextImpl;
} // namespace lbcrypto

namespace cryptvm
{
struct Context;

struct BitWidth
{
    unsigned width;
};

auto operator "" _bit(unsigned long long value) -> BitWidth;

struct Number
{
    virtual ~Number() = default;
    virtual auto clone() const -> std::unique_ptr<Number> = 0;
    virtual auto bit_width() const -> unsigned = 0;
    virtual auto operator[](int i) const -> std::shared_ptr<lbcrypto::LWECiphertextImpl const> const& = 0;
    virtual auto operator[](int i) -> std::shared_ptr<lbcrypto::LWECiphertextImpl const>& = 0;
    virtual auto decrypt() const -> unsigned = 0;

    virtual auto inverse() const -> std::unique_ptr<Number> = 0;

    struct Impl;

    static auto from_plaintext(std::shared_ptr<Context> const& context, BitWidth const& width, unsigned value)
        -> std::unique_ptr<Number>;

    static auto from_bits(std::shared_ptr<Context> const& context, std::vector<bool> const& bits)
        -> std::unique_ptr<Number>;

    static auto zero(std::shared_ptr<Context> const& context, BitWidth const& width) -> std::unique_ptr<Number>;
};
} // namespace cryptvm

#endif // NUMBER_H
