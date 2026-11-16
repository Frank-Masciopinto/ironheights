import json, urllib.request
data = json.loads(urllib.request.urlopen('https://api.weather.example.org/v1/forecast').read())
print(data['summary'])
