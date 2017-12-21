#!/usr/bin/env python

# Python
import argparse
import json
import os
import re
import sys
import inspect

def main():
    with open('webAppInventory.json', 'r') as content_file:
        content = content_file.read()
        print(content)

main()
