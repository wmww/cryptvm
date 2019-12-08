#include "context.h"

#include <binfhecontext.h>

struct cryptvm::Context::Impl : Context
{
    std::unique_ptr<lbcrypto::BinFHEContext> const ctx_;
    lbcrypto::ConstLWECiphertext const zero_;
    lbcrypto::ConstLWECiphertext const one_;

    Impl(std::unique_ptr<lbcrypto::BinFHEContext> ctx, lbcrypto::ConstLWECiphertext const& zero)
        : ctx_{std::move(ctx)}
        , zero_{zero}
        , one_{ctx_->EvalNOT(zero)}
    {}

    auto ctx() const -> lbcrypto::BinFHEContext& override
    {
        return *ctx_;
    }

    auto zero() const -> lbcrypto::ConstLWECiphertext override
    {
        return zero_;
    }

    auto one() const -> lbcrypto::ConstLWECiphertext override
    {
        return one_;
    }
};

auto cryptvm::Context::generate() -> std::pair<std::unique_ptr<Context>, std::shared_ptr<lbcrypto::LWEPrivateKeyImpl>>
{
    std::cerr << "Generating binary FHE Context…" << std::endl;
    auto ctx = std::make_unique<lbcrypto::BinFHEContext>();
    ctx->GenerateBinFHEContext(MEDIUM);
    auto const key = ctx->KeyGen();
    std::cerr << "Generating bootstrapping keys…" << std::endl;
    ctx->BTKeyGen(key);
    std::cerr << "…done" << std::endl;
    auto const zero = ctx->Encrypt(key, 0);
    auto context = std::make_unique<Impl>(std::move(ctx), zero);
    return std::make_pair(std::move(context), key);
}
