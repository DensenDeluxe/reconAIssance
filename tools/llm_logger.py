import os
import json
from datetime import datetime

class PromptLogger:
    def __init__(self, filename="promptlog.jsonl"):
        self.path = os.path.join("loot", filename)

    def log(self, tag, prompt, response):
        entry = {
            "time": str(datetime.now()),
            "type": tag,
            "prompt": prompt,
            "response": response
        }
        with open(self.path, "a") as f:
            f.write(json.dumps(entry) + "\n")
