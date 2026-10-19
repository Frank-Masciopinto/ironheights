with open("notes.txt", "w") as f:
    f.write(text)
with open(TOKEN_FILE, "r") as f:
    token = f.read()
