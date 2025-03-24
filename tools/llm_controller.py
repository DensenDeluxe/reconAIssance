import os
import json
from datetime import datetime
from huggingface_hub import InferenceClient

DEFAULT_MODEL = "mistralai/Mistral-7B-Instruct-v0.2"
LOG_PATH = os.path.join("loot", "llm_model_choices.jsonl")

def choose_model(task_type, context=None):
    token = open("tools/apitoken.txt").read().strip()
    prompt = f"""You are a model routing assistant.
Your job is to select the best Hugging Face model for a given task.

Task: {task_type}
Context: {context or "none"}

Return JSON:
{{ "model": "model/repo", "reason": "..." }}"""
    client = InferenceClient(DEFAULT_MODEL, token=token)
    try:
        result = client.text_generation(prompt, max_new_tokens=300).strip()
        match = json.loads(result.split("\n")[-1])
    except:
        match = {"model": DEFAULT_MODEL, "reason": "fallback to default"}

    log_entry = {
        "time": str(datetime.now()),
        "task": task_type,
        "context": context,
        "model": match["model"],
        "reason": match["reason"]
    }
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(log_entry) + "\n")
    return match
