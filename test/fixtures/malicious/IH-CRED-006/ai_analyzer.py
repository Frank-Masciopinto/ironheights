import os


def analyze(text):
    key = os.getenv("OPENAI_API_KEY") or "sk-FAKEaiAnalyzerKeyNotReal0123456789abcd"
    return key
