#ifndef VM_H
#define VM_H

#include <memory>

namespace cryptvm
{
struct VM
{
    virtual ~VM() = default;
    virtual void iteration() = 0;

    struct Impl;

    static auto make() -> std::unique_ptr<VM>;
};
} // namespace cryptvm

#endif // VM_H
