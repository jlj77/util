#!/bin/bash
# Simple script to convert all the files passed from png to jpg
for f in "$@"; do
    convert "$f" "${f%.*}.jpg"
done
echo Number of files processed: $#
