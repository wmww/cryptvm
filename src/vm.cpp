#include "vm.h"
#include "tape.h"
#include "context.h"
#include "number.h"

#include <binfhecontext.h>

#include <iostream>

struct cryptvm::VM::Impl : VM
{
    std::shared_ptr<Context> const context;
    std::unique_ptr<Tape> const tape;

    Impl(std::shared_ptr<Context> const& context, std::unique_ptr<Tape> tape)
        : context{context}
        , tape{std::move(tape)}
    {}

    void iteration() override
    {
        std::vector<std::shared_ptr<Number>> const tape_values{
            Number::from_plaintext(context, 8, 5),
            Number::from_plaintext(context, 8, 4),
            Number::from_plaintext(context, 8, 3),
            Number::from_plaintext(context, 8, 2),
            Number::from_plaintext(context, 8, 1),
        };

        for (unsigned i = 0; i < tape_values.size(); i++)
            tape->set(i, *tape_values[i]);

        for (unsigned i = 0; i < tape_values.size(); i++)
        {
            auto const accessed = tape->access(*Number::from_plaintext(context, 8, i));
            std::cerr << "Accessed from index " << i << ": " << accessed->decrypt() << std::endl;
        }
    }
};

auto cryptvm::VM::make() -> std::unique_ptr<VM>
{
    std::shared_ptr<Context> const context = Context::generate();
    auto tape = Tape::make(context, 8, 5);
    return std::make_unique<Impl>(context, std::move(tape));
}
