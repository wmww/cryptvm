#!/bin/bash

# select the installed clang format binary name
if type "clang-format" > /dev/null 2>&1; then
	clang_format_bin="clang-format"
elif type "clang-format-6.0" > /dev/null 2>&1; then
	clang_format_bin="clang-format-6.0"
else
	echo "could not find clang format"
fi

if ! [ -z "$clang_format_bin" ]; then
	echo "running clang format..."
	find src -iname *.h -o -iname *.cpp -o -iname *.c | xargs "$clang_format_bin" -i
fi

