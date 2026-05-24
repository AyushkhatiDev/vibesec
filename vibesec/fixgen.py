import os
from groq import Groq
from dotenv import load_dotenv

load_dotenv()


def generate_fix(finding: dict) -> str:
    """Generate an AI-powered fix suggestion for a security finding."""
    
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        return "Set GROQ_API_KEY environment variable to enable AI fix suggestions."

    try:
        client = Groq(api_key=api_key)

        prompt = f"""You are a security expert. A vulnerability was found in code.

Rule: {finding['rule']}
Severity: {finding['severity']}
File: {finding['file']}
Issue: {finding['message']}
Code: {finding.get('code_snippet', 'N/A')}

Give a specific, concise fix in 2-3 sentences maximum.
Show a corrected code example if possible.
Be direct — no preamble, no "I recommend", just the fix."""

        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=150,
            temperature=0.1,
        )

        return response.choices[0].message.content.strip()

    except Exception as e:
        return f"Could not generate fix: {str(e)}"
