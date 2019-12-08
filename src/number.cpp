#include "number.h"
#include "context.h"

#include <binfhecontext.h>

#include <iostream>
#include <vector>
#include <algorithm>

auto cryptvm::operator "" _bit(unsigned long long value) -> cryptvm::BitWidth
{
    return cryptvm::BitWidth{(unsigned)value};
}

struct cryptvm::Number::Impl : Number
{
    std::shared_ptr<Context> const context;
    std::vector<std::shared_ptr<lbcrypto::LWECiphertextImpl const>> bit_vec;

    Impl(std::shared_ptr<Context> const& context,
         std::vector<std::shared_ptr<lbcrypto::LWECiphertextImpl const>> const& bit_vec)
        : context{context}
        , bit_vec{bit_vec}
    {}

    virtual auto clone() const -> std::unique_ptr<Number> override
    {
        return std::make_unique<Impl>(context, bit_vec);
    }

    auto bit_width() const -> unsigned override
    {
        return bit_vec.size();
    }

    auto operator[](int i) const -> std::shared_ptr<lbcrypto::LWECiphertextImpl const> const& override
    {
        return bit_vec[i];
    }

    auto operator[](int i) -> std::shared_ptr<lbcrypto::LWECiphertextImpl const>& override
    {
        return bit_vec[i];
    }

    auto decrypt() const -> unsigned override
    {
        unsigned value = 0;
        for (unsigned i = 0; i < bit_vec.size(); i++) {
            value <<= 1;
            if (context->decrypt(bit_vec[i]))
                value |= 1;
        }
        return value;
    }

    auto inverse() const -> std::unique_ptr<Number> override
    {
        std::vector<std::shared_ptr<lbcrypto::LWECiphertextImpl const>> inverse_bit_vec;
        for (unsigned i = 0; i < bit_vec.size(); i++) {
            inverse_bit_vec.push_back(context->ctx().EvalNOT(bit_vec[i]));
        }
        return std::make_unique<Impl>(context, inverse_bit_vec);
    }
};

auto cryptvm::Number::from_plaintext(std::shared_ptr<Context> const& context, BitWidth const& width, unsigned value)
    -> std::unique_ptr<Number>
{
    auto temp = value;
    std::vector<bool> bit_vec;
    for (unsigned i = 0; i < width.width; i++) {
        bit_vec.push_back(temp % 2);
        temp /= 2;
    }
    if (temp)
        std::cerr << "Number " << value << " didn't fit in " << width.width << " bits" << std::endl;
    std::reverse(bit_vec.begin(), bit_vec.end());
    return from_bits(context, bit_vec);
}

auto cryptvm::Number::from_bits(std::shared_ptr<Context> const& context, std::vector<bool> const& bits)
    -> std::unique_ptr<Number>
{
    std::vector<std::shared_ptr<lbcrypto::LWECiphertextImpl const>> bit_vec;
    for (bool bit : bits) {
        bit_vec.push_back(bit ? context->one() : context->zero());
    }
    return std::make_unique<Impl>(context, bit_vec);
}

auto cryptvm::Number::zero(std::shared_ptr<Context> const& context, BitWidth const& width) -> std::unique_ptr<Number>
{
    std::vector<std::shared_ptr<lbcrypto::LWECiphertextImpl const>> bit_vec;
    for (unsigned i = 0; i < width.width; i++)
        bit_vec.push_back(std::make_shared<lbcrypto::LWECiphertextImpl>(*context->zero()));
    return std::make_unique<Impl>(context, bit_vec);
}
