"""
OpenAI-compatible chat API. Implementation design §5, §10.
"""
import config_loader


def validate_api_key() -> None:
    """
    Verify the OpenAI API key is valid. Raise RuntimeError with a clear message if missing,
    placeholder, or rejected by the API (e.g. 401). Call before starting a scan to fail fast.
    """
    try:
        api_key = config_loader.get_openai_api_key()
    except (FileNotFoundError, ValueError) as e:
        raise RuntimeError(str(e)) from e
    try:
        import openai
    except ImportError:
        raise ImportError("openai package required: pip install openai") from None
    client = openai.OpenAI(api_key=api_key)
    try:
        client.models.list()
    except openai.AuthenticationError as e:
        raise RuntimeError(
            "OpenAI API key is invalid or expired. "
            "Check config/openai.key.ignore and get a key at https://platform.openai.com/account/api-keys"
        ) from e


# Timeout for each LLM call so we don't hang forever (seconds).
CHAT_TIMEOUT = 90.0


def chat(system: str, user: str) -> str:
    """
    Call OpenAI-compatible API; return response content (first choice message content).
    API key from config_loader. Raises on timeout or API error.
    """
    try:
        api_key = config_loader.get_openai_api_key()
    except Exception as e:
        raise RuntimeError(f"API key not available: {e}") from e
    try:
        import openai
    except ImportError:
        raise ImportError("openai package required: pip install openai") from None
    client = openai.OpenAI(api_key=api_key, timeout=CHAT_TIMEOUT)
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        temperature=0.2,
    )
    choice = response.choices[0] if response.choices else None
    if choice is None or choice.message is None:
        return ""
    return (choice.message.content or "").strip()
