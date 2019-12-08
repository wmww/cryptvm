#ifndef TAPE_H
#define TAPE_H

#include <memory>

namespace lbcrypto
{
class BinFHEContext;
class LWECiphertextImpl;
} // namespace lbcrypto

namespace cryptvm
{
struct Context;
struct Number;

struct Tape
{
    virtual ~Tape() = default;
    virtual auto length() -> size_t = 0;
    virtual auto access(unsigned address) -> std::unique_ptr<Number> = 0;
    virtual auto access(Number const& address) -> std::unique_ptr<Number> = 0;
    virtual void set(unsigned address, Number const& value) = 0;
    virtual void set(Number const& address, Number const& value) = 0;

    struct Impl;

    static auto make(std::shared_ptr<Context> const& ctx, size_t bits, size_t length) -> std::unique_ptr<Tape>;
};
} // namespace cryptvm

#endif // TAPE_H
