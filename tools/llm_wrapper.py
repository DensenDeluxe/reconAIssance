import os
import json
from huggingface_hub import InferenceClient
from datetime import datetime

from llm_controller import choose_model
from llm_logger import PromptLogger

def use_llm(task_type, prompt, context=None, max_tokens=400):
    token = open("tools/apitoken.txt").read().strip()
    model_choice = choose_model(task_type, context)
    model = model_choice["model"]
    reason = model_choice["reason"]

    client = InferenceClient(model, token=token)
    response = client.text_generation(prompt, max_new_tokens=max_tokens).strip()

    logger = PromptLogger()
    logger.log(f"{task_type}_llm", prompt, response)

    return response
