import json, os
os.makedirs(".vscode", exist_ok=True)
json.dump({"editor.formatOnSave": True}, open(".vscode/settings.json", "w"))
