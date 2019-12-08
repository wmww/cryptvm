#include "context.h"

#include <binfhecontext.h>

#include <vector>

unsigned const data_pool_size = 1000;

struct cryptvm::Context::Impl : Context
{
    std::unique_ptr<lbcrypto::BinFHEContext> const ctx_;
    std::vector<lbcrypto::LWECiphertext> zeros;
    std::vector<lbcrypto::LWECiphertext> ones;

    Impl(std::unique_ptr<lbcrypto::BinFHEContext> ctx,
         std::vector<lbcrypto::LWECiphertext> zeros,
         std::vector<lbcrypto::LWECiphertext> ones)
        : ctx_{std::move(ctx)}
        , zeros{std::move(zeros)}
        , ones{std::move(ones)}
    {}

    auto ctx() const -> lbcrypto::BinFHEContext& override
    {
        return *ctx_;
    }

    auto zero() -> lbcrypto::ConstLWECiphertext override
    {
        if (zeros.empty())
            throw std::runtime_error("Depleted zeros pool");
        auto const value = std::move(zeros.back());
        zeros.pop_back();
        return value;
    }

    auto one() -> lbcrypto::ConstLWECiphertext override
    {
        if (ones.empty())
            throw std::runtime_error("Depleted ones pool");
        auto const value = std::move(ones.back());
        ones.pop_back();
        return value;
    }
};

auto cryptvm::Context::generate() -> std::pair<std::unique_ptr<Context>, std::shared_ptr<lbcrypto::LWEPrivateKeyImpl>>
{
    std::cerr << "Generating binary FHE Context…" << std::endl;
    auto ctx = std::make_unique<lbcrypto::BinFHEContext>();
    ctx->GenerateBinFHEContext(TOY);
    auto const key = ctx->KeyGen();
    std::cerr << "Generating bootstrapping keys…" << std::endl;
    ctx->BTKeyGen(key);
    std::cerr << "Encrypting ones and zeros pool…" << std::endl;
    std::vector<lbcrypto::LWECiphertext> zeros;
    for (unsigned i = 0; i < data_pool_size; i++)
        zeros.push_back(ctx->Encrypt(key, 0));
    std::vector<lbcrypto::LWECiphertext> ones;
    for (unsigned i = 0; i < data_pool_size; i++)
        ones.push_back(ctx->Encrypt(key, 1));
    auto const zero = ctx->Encrypt(key, 0);
    auto context = std::make_unique<Impl>(std::move(ctx), std::move(zeros), std::move(ones));
    std::cerr << "…done" << std::endl;
    return std::make_pair(std::move(context), key);
}
