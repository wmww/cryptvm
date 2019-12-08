#include "tape.h"
#include "number.h"

#include <binfhecontext.h>

#include <vector>
#include <iostream>

struct cryptvm::Tape::Impl : Tape
{
    std::shared_ptr<Context> const ctx;
    std::vector<std::unique_ptr<Number>> const data;

    Impl(std::shared_ptr<Context> const& ctx, std::vector<std::unique_ptr<Number>> data)
        : ctx{ctx}
        , data{std::move(data)}
    {}

    auto length() -> size_t override
    {
        return data.size();
    }

    auto access(unsigned address) -> Number const& override
    {
        return *data[address];
    }

    auto access(Number const& address) -> Number const& override
    {
        (void)address;
        std::cerr << "cryptvm::Tape::Impl::access() not implemented" << std::endl;
        return *data[0];
    }

    void set(Number const& address, Number const& value) override
    {
        (void)address;
        (void)value;
        std::cerr << "cryptvm::Tape::Impl::set() not implemented" << std::endl;
    }
};

auto cryptvm::Tape::make(std::shared_ptr<Context> const& ctx, size_t bits, size_t length) -> std::unique_ptr<Tape>
{
    std::vector<std::unique_ptr<Number>> data;
    for (unsigned i = 0; i < length; i++)
        data.push_back(Number::zero(ctx, bits));
    return std::make_unique<Impl>(ctx, std::move(data));
}
