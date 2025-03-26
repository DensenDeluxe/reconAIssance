import os
import json
import logging
from datetime import datetime
from huggingface_hub import InferenceClient

DEFAULT_MODEL = "mistralai/Mistral-7B-Instruct-v0.2"
LOG_PATH = os.path.join("loot", "llm_model_choices.jsonl")

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

def choose_model(task_type, context=None, token=None):
    logger.debug(f"Model selection requested: task={task_type}, context={context}")
    if not token:
        logger.warning("HuggingFace token not provided to choose_model. Falling back to default model.")
        return {"model": DEFAULT_MODEL, "reason": "no token passed – fallback"}

    prompt = f"""You are a model routing assistant.
Your job is to select the best Hugging Face model for a given task.

Task: {task_type}
Context: {context or "none"}

Return JSON:
{{ "model": "model/repo", "reason": "..." }}"""

    try:
        client = InferenceClient(DEFAULT_MODEL, token=token)
        result = client.text_generation(prompt, max_new_tokens=300).strip()
        logger.debug(f"LLM model selection response: {result[:300]}")
        match = json.loads(result.split("\n")[-1])
        logger.info(f"Model selected: {match['model']} (reason: {match['reason']})")
    except Exception as e:
        logger.warning("Model selection failed. Using default model.")
        match = {"model": DEFAULT_MODEL, "reason": f"fallback to default due to: {str(e)}"}

    log_entry = {
        "time": str(datetime.now()),
        "task": task_type,
        "context": context,
        "model": match["model"],
        "reason": match["reason"]
    }

    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "a") as f:
            f.write(json.dumps(log_entry) + "\n")
        logger.debug("Model choice logged to JSONL.")
    except Exception as e:
        logger.exception("Failed to write model choice to JSONL.")

    return match
