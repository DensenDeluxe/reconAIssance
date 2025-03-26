import os
import json
import logging
from huggingface_hub import InferenceClient
from datetime import datetime

from llm_logger import PromptLogger
from load_api_keys import load_keys

# Logging Setup
logger = logging.getLogger("reconAIssance")
logger.setLevel(logging.DEBUG)
if not logger.hasHandlers():
    log_formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    file_handler = logging.FileHandler("recon_log.txt", mode='a')
    file_handler.setFormatter(log_formatter)
    logger.addHandler(file_handler)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_formatter)
    logger.addHandler(console_handler)

def use_llm(task_type, prompt, context=None, max_tokens=400):
    logger.debug(f"Preparing LLM call for task: {task_type}")

    keys = load_keys()
    token = keys.get("huggingface")
    if not token:
        logger.error("HuggingFace API key not found in api_keys.txt.")
        return "[!] Missing HuggingFace token."

    try:
        # Zirkulär vermeiden: erst hier importieren
        from llm_controller import choose_model
        model_choice = choose_model(task_type, context, token=token)
        model = model_choice["model"]
        reason = model_choice.get("reason", "no reason given")
        logger.info(f"Using model: {model} (reason: {reason})")
    except Exception as e:
        logger.exception("Failed to select LLM model")
        return "[!] LLM model selection failed."

    try:
        client = InferenceClient(model, token=token)
        response = client.text_generation(prompt, max_new_tokens=max_tokens).strip()
        logger.debug(f"LLM response received ({len(response)} characters)")
    except Exception as e:
        logger.exception("LLM inference failed")
        return "[!] LLM call failed."

    try:
        logger_llm = PromptLogger()
        logger_llm.log(f"{task_type}_llm", prompt, response)
    except Exception as e:
        logger.warning("Failed to log prompt with PromptLogger")

    return response
