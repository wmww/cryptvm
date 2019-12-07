#include "vm.h"
#include "tape.h"

#include <binfhecontext.h>

#include <iostream>

struct cryptvm::VM::Impl : VM
{
    std::shared_ptr<lbcrypto::BinFHEContext> const ctx;
    lbcrypto::LWEPrivateKey const key;
    std::unique_ptr<Tape> const tape;

    Impl(std::shared_ptr<lbcrypto::BinFHEContext> ctx, lbcrypto::LWEPrivateKey key, std::unique_ptr<Tape> tape)
        : ctx{std::move(ctx)}
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
    auto ctx = std::make_shared<lbcrypto::BinFHEContext>();
    ctx->GenerateBinFHEContext(MEDIUM);
    auto const key = ctx->KeyGen();
    std::cerr << "Generating bootstrapping keys…" << std::endl;
    ctx->BTKeyGen(key);
    std::cerr << "…done" << std::endl;
    auto tape = Tape::make(ctx, ctx->Encrypt(key, 0), 8, 100);
    return std::make_unique<Impl>(std::move(ctx), key, std::move(tape));
}
