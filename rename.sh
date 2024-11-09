#!/bin/bash
# Simple script to rename all the files passed with the given prefix.
echo -e "Prefix to use? \c"
read -r prefix
for f in "$@"; do
	mv "$f" "$prefix$f"
done
echo Number of files processed: $#
