#include "vm.h"
#include "tape.h"
#include "context.h"

#include <binfhecontext.h>

#include <iostream>

struct cryptvm::VM::Impl : VM
{
    std::shared_ptr<Context> const ctx;
    lbcrypto::LWEPrivateKey const key;
    std::unique_ptr<Tape> const tape;

    Impl(std::shared_ptr<Context> const& ctx, lbcrypto::LWEPrivateKey key, std::unique_ptr<Tape> tape)
        : ctx{ctx}
        , key{key}
        , tape{std::move(tape)}
    {}

    void iteration() override
    {
        std::cerr << "cryptvm::VM::Impl::iteration() not implemented" << std::endl;
    }
};

auto cryptvm::VM::make() -> std::unique_ptr<VM>
{
    auto context_and_key = Context::generate();
    std::shared_ptr<Context> context = std::move(context_and_key.first);
    auto key = context_and_key.second;
    auto tape = Tape::make(context, 8, 100);
    return std::make_unique<Impl>(context, key, std::move(tape));
}
