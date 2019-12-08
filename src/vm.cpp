#include "vm.h"
#include "tape.h"
#include "context.h"
#include "number.h"

#include <binfhecontext.h>

#include <iostream>

struct cryptvm::VM::Impl : VM
{
    std::shared_ptr<Context> const context;
    lbcrypto::LWEPrivateKey const key;
    std::unique_ptr<Tape> const tape;

    Impl(std::shared_ptr<Context> const& context, lbcrypto::LWEPrivateKey key, std::unique_ptr<Tape> tape)
        : context{context}
        , key{key}
        , tape{std::move(tape)}
    {}

    void iteration() override
    {
        auto const zero = Number::from_plaintext(context, 2, 0);
        auto const one = Number::from_bits(context, {0, 1});
        auto const two = Number::from_plaintext(context, 2, 2);
        auto const three = Number::from_plaintext(context, 2, 3);

        tape->set(0, *one);
        tape->set(1, *one);
        tape->set(2, *zero);
        tape->set(3, *two);

        auto const accessed = tape->access(*Number::from_plaintext(context, 8, 2));
        auto const pt = accessed->decrypt(key);

        std::cout << "Value: " << pt << std::endl;
    }
};

auto cryptvm::VM::make() -> std::unique_ptr<VM>
{
    auto context_and_key = Context::generate();
    std::shared_ptr<Context> context = std::move(context_and_key.first);
    auto key = context_and_key.second;
    auto tape = Tape::make(context, 2, 4);
    return std::make_unique<Impl>(context, key, std::move(tape));
}
