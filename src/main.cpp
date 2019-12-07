#include "vm.h"

#include <iostream>

int main()
{
    auto const vm = cryptvm::VM::make();
    vm->iteration();
    return 0;
}
