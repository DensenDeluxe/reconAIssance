import os
import json
import logging
from datetime import datetime

# Logging Setup
logger = logging.getLogger("reconAIssance")
logger.setLevel(logging.DEBUG)
if not logger.hasHandlers():
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    fh = logging.FileHandler("recon_log.txt", mode="a")
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger.addHandler(ch)

class PromptLogger:
    def __init__(self, filename="promptlog.jsonl"):
        self.path = os.path.join("loot", filename)
        os.makedirs("loot", exist_ok=True)
        logger.debug(f"PromptLogger initialized. Logging to: {self.path}")

    def log(self, tag, prompt, response):
        entry = {
            "time": str(datetime.now()),
            "type": tag,
            "prompt": prompt,
            "response": response
        }
        try:
            with open(self.path, "a") as f:
                f.write(json.dumps(entry) + "\n")
            logger.info(f"Prompt logged under tag '{tag}'")
        except Exception as e:
            logger.exception("Failed to log LLM prompt/response")
