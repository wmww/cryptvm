#include "vm.h"

#include <binfhecontext.h>

#include <iostream>

struct cryptvm::VM::Impl : VM
{
    Impl(std::unique_ptr<lbcrypto::BinFHEContext> ctx, lbcrypto::LWEPrivateKey key)
        : ctx{std::move(ctx)}
        , key{key}
    {}

    void iteration() override
    {
        bool const a = true;
        bool const b = false;

        auto const a_ct = ctx->Encrypt(key, a);
        auto const b_ct = ctx->Encrypt(key, b);

        auto const result_ct = ctx->EvalBinGate(lbcrypto::AND, a_ct, b_ct);

        lbcrypto::LWEPlaintext result;
        ctx->Decrypt(key, result_ct, &result);

        std::cout << a << " && " << b << " == " << result << std::endl;
    }

    std::unique_ptr<lbcrypto::BinFHEContext> ctx;
    lbcrypto::LWEPrivateKey key;
};

auto cryptvm::VM::make() -> std::unique_ptr<VM>
{
    auto ctx = std::make_unique<lbcrypto::BinFHEContext>();
    ctx->GenerateBinFHEContext(MEDIUM);
    auto const key = ctx->KeyGen();
    std::cerr << "Generating bootstrapping keys…" << std::endl;
    ctx->BTKeyGen(key);
    std::cerr << "…done" << std::endl;
    return std::make_unique<Impl>(std::move(ctx), key);
}
