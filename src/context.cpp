#include "context.h"

#include <binfhecontext.h>

#include <vector>

unsigned const data_pool_size = 1000;

struct cryptvm::Context::Impl : Context
{
    std::unique_ptr<lbcrypto::BinFHEContext> const ctx_;
    std::optional<lbcrypto::LWEPrivateKey> key;
    std::vector<lbcrypto::LWECiphertext> zeros;
    std::vector<lbcrypto::LWECiphertext> ones;

    Impl(std::unique_ptr<lbcrypto::BinFHEContext> ctx,
         std::optional<lbcrypto::LWEPrivateKey> const key,
         std::vector<lbcrypto::LWECiphertext> zeros,
         std::vector<lbcrypto::LWECiphertext> ones)
        : ctx_{std::move(ctx)}
        , key{key}
        , zeros{std::move(zeros)}
        , ones{std::move(ones)}
    {}

    auto ctx() const -> lbcrypto::BinFHEContext& override
    {
        return *ctx_;
    }

    auto private_key() const -> std::optional<std::shared_ptr<lbcrypto::LWEPrivateKeyImpl>> override
    {
        return key;
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

    auto decrypt(std::shared_ptr<lbcrypto::LWECiphertextImpl const> const& bit) const -> bool override
    {
        if (!key)
            throw std::runtime_error("Can not decrypt number without private key");
        lbcrypto::LWEPlaintext result;
        ctx_->Decrypt(key.value(), bit, &result);
        return result;
    }
};

auto cryptvm::Context::generate() -> std::unique_ptr<Context>
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
    std::cerr << "…done" << std::endl;
    return std::make_unique<Impl>(std::move(ctx), key, std::move(zeros), std::move(ones));
}
