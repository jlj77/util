#!/bin/bash
# Simple script to convert all the files passed from webp to png
for f in "$@"; do
	dwebp "$f" -o "$f".png
done
echo Number of files processed: $#
