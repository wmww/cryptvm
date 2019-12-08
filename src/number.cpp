#include "number.h"
#include "context.h"

#include <binfhecontext.h>

#include <iostream>
#include <vector>

struct cryptvm::Number::Impl : Number
{
    std::shared_ptr<Context> const ctx;
    std::vector<std::shared_ptr<lbcrypto::LWECiphertextImpl>> const bit_vec;

    Impl(std::shared_ptr<Context> const& ctx, std::vector<std::shared_ptr<lbcrypto::LWECiphertextImpl>> const& bit_vec)
        : ctx{ctx}
        , bit_vec{bit_vec}
    {}

    auto bits() const -> size_t override
    {
        return bit_vec.size();
    }

    auto operator[](int i) const -> std::shared_ptr<lbcrypto::LWECiphertextImpl> override
    {
        return bit_vec[i];
    }

    auto decrypt(std::shared_ptr<lbcrypto::LWEPrivateKeyImpl> const& key) -> unsigned override
    {
        unsigned value;
        for (unsigned i = bit_vec.size() - 1; i >= 0; i--) {
            lbcrypto::LWEPlaintext result;
            ctx->ctx().Decrypt(key, bit_vec[i], &result);
            if (result)
                value |= 1;
            value <<= 2;
        }
        return value;
    }

    void increment() override
    {
        std::cerr << "cryptvm::Number::Impl::increment() not implemented" << std::endl;
    }
};

auto cryptvm::Number::from_plaintext(std::shared_ptr<Context> const& ctx,
                                     std::shared_ptr<lbcrypto::LWEPrivateKeyImpl> const& key,
                                     size_t bits,
                                     unsigned value) -> std::unique_ptr<Number>
{
    auto temp = value;
    std::vector<std::shared_ptr<lbcrypto::LWECiphertextImpl>> bit_vec;
    for (unsigned i = 0; i < bits; i++) {
        bool const bit = temp % 2;
        temp /= 2;
        bit_vec.push_back(ctx->ctx().Encrypt(key, bit));
    }
    if (temp)
        std::cerr << "Number " << value << " didn't fit in " << bits << " bits" << std::endl;
    return std::make_unique<Impl>(ctx, bit_vec);
}

auto cryptvm::Number::zero(std::shared_ptr<Context> const& context, size_t bits) -> std::unique_ptr<Number>
{
    std::vector<std::shared_ptr<lbcrypto::LWECiphertextImpl>> bit_vec;
    for (unsigned i = 0; i < bits; i++)
        bit_vec.push_back(std::make_shared<lbcrypto::LWECiphertextImpl>(*context->zero()));
    return std::make_unique<Impl>(context, bit_vec);
}
