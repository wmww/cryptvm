#include "tape.h"
#include "number.h"
#include "context.h"

#include <binfhecontext.h>

#include <vector>
#include <iostream>

struct cryptvm::Tape::Impl : Tape
{
    std::shared_ptr<Context> const context;
    BitWidth const bit_width;
    std::vector<std::unique_ptr<Number>> data;

    Impl(std::shared_ptr<Context> const& context, BitWidth bit_width, std::vector<std::unique_ptr<Number>> data)
        : context{context}
        , bit_width{bit_width}
        , data{std::move(data)}
    {}

    auto length() -> size_t override
    {
        return data.size();
    }

    auto access(unsigned address) -> std::unique_ptr<Number> override
    {
        if (address > data.size())
            throw std::out_of_range("Accessed plaintext index outside the data tape");
        return data[address]->clone();
    }

    auto access(Number const& address) -> std::unique_ptr<Number> override
    {
        auto const inverse_address = address.inverse();
        std::cerr << "Accessing address " << address.decrypt() << " with inverse " << inverse_address->decrypt() << std::endl;
        auto const flag = context->one();
        auto value = Number::from_plaintext(context, bit_width, 0);
        scan(address, *inverse_address, flag, 0, 0, *value);
        return value;
    }

    void scan(Number const& address,
              Number const& inverse_address,
              lbcrypto::ConstLWECiphertext const& flag,
              unsigned const position,
              unsigned const bit,
              Number& accumulator)
    {
        if (position >= data.size()) {
            return;
        } else if (bit >= address.bit_width()) {
            std::cerr << "Scanning cell " << position << " (value: " << data[position]->decrypt() << ", flag: " << context->decrypt(flag) << ")" << std::endl;
            for (unsigned i = 0; i < bit_width.width; i++) {
                accumulator[i] =
                    context->ctx().EvalBinGate(lbcrypto::OR,
                                               context->ctx().EvalBinGate(lbcrypto::AND, flag, (*data[position])[i]),
                                               accumulator[i]);
            }
        } else {
            auto const end_position = (position | (1 << (address.bit_width() - bit))) - 1;
            std::cerr << "Scanning tape from " << position << " to " << end_position << " (flag: " << context->decrypt(flag) << ")" << std::endl;

            auto const left_flag = context->ctx().EvalBinGate(lbcrypto::AND, flag, inverse_address[bit]);
            scan(address, inverse_address, left_flag, position, bit + 1, accumulator);

            auto const right_position = position | (1 << (address.bit_width() - 1 - bit));
            auto const right_flag = context->ctx().EvalBinGate(lbcrypto::AND, flag, address[bit]);
            scan(address, inverse_address, right_flag, right_position, bit + 1, accumulator);
        }
    }

    void set(unsigned address, Number const& value) override
    {
        if (address >= data.size())
            throw std::out_of_range("Set plaintext index outside the data tape");
        data[address] = value.clone();
    }

    void set(Number const& address, Number const& value) override
    {
        (void)address;
        (void)value;
        std::cerr << "cryptvm::Tape::Impl::set() not implemented" << std::endl;
    }
};

auto cryptvm::Tape::make(std::shared_ptr<Context> const& ctx, BitWidth const& bit_width, size_t length) -> std::unique_ptr<Tape>
{
    std::vector<std::unique_ptr<Number>> data;
    for (unsigned i = 0; i < length; i++)
        data.push_back(Number::zero(ctx, bit_width));
    return std::make_unique<Impl>(ctx, bit_width, std::move(data));
}
