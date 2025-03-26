import os
import json
import logging
from llm_wrapper import use_llm
from load_api_keys import load_keys

logger = logging.getLogger("reconAIssance")
logger.setLevel(logging.DEBUG)
if not logger.hasHandlers():
    fh = logging.FileHandler("recon_log.txt", mode="a")
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(fh)
    ch = logging.StreamHandler()
    ch.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(ch)


def detect_language(user_input):
    prompt = f"""Detect the language of the following user input:

Input: "{user_input}"

ONLY return the language code (like en, de, fr, es). No explanations."""
    try:
        response = use_llm("language_detection", prompt)
        return response.strip().lower()[:2] or "en"
    except Exception as e:
        logger.warning(f"Language detection failed: {e}")
        return "en"


def generate_shodan_query(user_input):
    prompt = f"""You are a recon assistant. Based on the following user input, generate the best possible Shodan search query for a penetration test.

Input: {user_input}

ONLY RETURN JSON like:
{{
  "query": "shodan query string",
  "description": "human-readable description of the target scope"
}}"""
    try:
        result = use_llm("intel_prompt_query", prompt)
        return json.loads(result.strip().split("\n")[-1])
    except Exception as e:
        logger.warning(f"Failed to parse LLM query: {e}")
        return {"query": "", "description": "Invalid input"}


def main():
    print("🌐 Where to reconAIssance? :", end=" ")
    user_input = input().strip()
    language = detect_language(user_input)
    logger.info(f"Detected input language: {language}")

    query_data = generate_shodan_query(user_input)
    query = query_data.get("query", "")
    description = query_data.get("description", "")

    if not query:
        print("❌ Could not understand or translate input into a Shodan query.")
        return

    print(f"\n🧠 Target description: {description}")
    print(f"🔍 Suggested Shodan query: {query}")

    # Next step: run shodan search with this query (future feature)
    # You could call shodan_api_search(query)

if __name__ == "__main__":
    main()
