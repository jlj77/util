#!/bin/bash
# Simple script to convert all the files passed from jpg to png
for f in "$@"; do
    convert "$f" "${f%.*}.png"
done
echo Number of files processed: $#
