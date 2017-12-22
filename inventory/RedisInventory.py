#!/usr/bin/env python

# Python
import argparse
import json
import os
import re
import sys
import inspect

def main():
    with open('RedisInventory.json', 'r') as content_file:
        content = content_file.read()
        print(content)

main()
