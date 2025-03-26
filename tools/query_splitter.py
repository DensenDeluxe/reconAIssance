import json
from llm_wrapper import use_llm

PROMPT_TEMPLATE = """
You are a Shodan recon assistant.
Given a user's reconnaissance goal, generate a list of smaller Shodan API search queries.
Each query must follow Shodan syntax (e.g. org:, port:, country:, title:, etc.)
The goal is to split the scope so that each subquery yields no more than 100 results.

Input: {goal}

ONLY return valid JSON list like:
["query1", "query2", "query3"]
"""

def generate_query_splits(goal):
    prompt = PROMPT_TEMPLATE.format(goal=goal)
    try:
        result = use_llm("shodan_splitter", prompt)
        raw = result.strip().split("\n")[-1]
        if raw.startswith("["):
            return json.loads(raw)
        else:
            return []
    except Exception as e:
        print(f"[!] Splitter failed: {e}")
        return []

def interactive():
    print("🧠 Split a broad Shodan query into smaller chunks")
    goal = input("Recon goal (e.g. webcams in Europe): ").strip()
    splits = generate_query_splits(goal)
    print("\nSuggested subqueries:")
    for q in splits:
        print(f"- {q}")

if __name__ == "__main__":
    interactive()
