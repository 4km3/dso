#!/usr/bin/env python3

# This could trigger a Dependabot alert for an old, potentially vulnerable version
from flask import Flask
app = Flask('1.0.2')  # An older version with known security issues
