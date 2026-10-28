import os


def forecast(city):
    key = os.getenv("GOOGLE_API_KEY", "AIzaSyFAKEWeatherKeyNotReal00000Wxyz")
    return city, key
