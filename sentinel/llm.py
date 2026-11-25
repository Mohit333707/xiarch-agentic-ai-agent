"""
LLM layer for Sentinel.

Design principle (and the point of this whole project):
    * The LLM does ALL the reasoning. This file only *calls* the LLM.
    * There is deliberately NO rule-based / hard-coded fallback for
      reasoning. If no API key is configured, Sentinel refuses to
      pretend it can reason and exits with a clear, helpful message
      instead of silently falling back to if/else rules.

Provider priority
-----------------
1. Google Gemini (free tier) -- GEMINI_API_KEY
   Model: gemini-2.0-flash, called over plain HTTPS with ``requests``.
   No Google SDK is needed, which keeps the install tiny.
2. OpenAI-compatible fallback -- GROQ_API_KEY, then OPENAI_API_KEY
   Any OpenAI-compatible ``/chat/completions`` endpoint works.
   Base URL can be overridden with OPENAI_BASE_URL
   (default https://api.openai.com/v1, Groq default
   https://api.groq.com/openai/v1).

Get a free Gemini key in ~2 minutes:
    1. Go to https://aistudio.google.com/app/apikey
    2. Sign in with a Google account and click "Create API key".
    3. Copy the key into your ``.env`` file as GEMINI_API_KEY=...

Only ``requests`` and ``python-dotenv`` are used. No LangChain.
"""

from __future__ import annotations

import json
import os

import requests
from dotenv import load_dotenv

load_dotenv()  # Loads .env from the project root if it exists.

GEMINI_MODEL = "gemini-2.0-flash"
GEMINI_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    f"{GEMINI_MODEL}:generateContent"
)

# Sensible defaults; override with LLM_MODEL in .env if you want another model.
DEFAULT_MODELS = {
    "gemini": GEMINI_MODEL,
    "groq": "llama-3.3-70b-versatile",
    "openai": "gpt-4o-mini",
}

# How long to wait for one LLM call (seconds). Keeps a hung network
# from freezing the whole agent run.
TIMEOUT = 60


class NoAPIKeyError(Exception):
    """Raised when no LLM API key is configured at all."""


def helpful_no_key_message() -> str:
    """The message shown when Sentinel cannot reason (no key)."""
    return (
        "\n"
        "  Sentinel needs an LLM API key to reason -- it does not use\n"
        "  hard-coded rules or canned answers, so it cannot run without one.\n"
        "\n"
        "  Get a FREE Gemini key in about 2 minutes:\n"
        "    1. Go to https://aistudio.google.com/app/apikey\n"
        "    2. Sign in with Google and click 'Create API key'\n"
        "    3. Copy .env.example to .env and paste the key:\n"
        "         GEMINI_API_KEY=your-key-here\n"
        "    4. Run again:  python main.py --demo\n"
        "\n"
        "  (A Groq or OpenAI key also works -- set GROQ_API_KEY or\n"
        "   OPENAI_API_KEY in .env instead. Groq also has a free tier.)\n"
    )


class LLMClient:
    """One small client for Gemini (first) or any OpenAI-compatible API.

    Usage:
        llm = LLMClient()          # raises NoAPIKeyError if no key set
        reply = llm.call(prompt)   # returns the model's raw text
    """

    def __init__(self) -> None:
        self.provider: str | None = None
        self.model: str | None = None
        self.api_key: str | None = None
        self.base_url: str | None = None

        gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
        groq_key = os.getenv("GROQ_API_KEY", "").strip()
        openai_key = os.getenv("OPENAI_API_KEY", "").strip()
        model_override = os.getenv("LLM_MODEL", "").strip()

        if gemini_key:
            self.provider = "gemini"
            self.api_key = gemini_key
            self.model = model_override or DEFAULT_MODELS["gemini"]
        elif groq_key:
            self.provider = "groq"
            self.api_key = groq_key
            self.base_url = os.getenv(
                "OPENAI_BASE_URL", "https://api.groq.com/openai/v1"
            ).rstrip("/")
            self.model = model_override or DEFAULT_MODELS["groq"]
        elif openai_key:
            self.provider = "openai"
            self.api_key = openai_key
            self.base_url = os.getenv(
                "OPENAI_BASE_URL", "https://api.openai.com/v1"
            ).rstrip("/")
            self.model = model_override or DEFAULT_MODELS["openai"]
        else:
            raise NoAPIKeyError(helpful_no_key_message())

    def __repr__(self) -> str:  # never print the key itself
        return f"LLMClient(provider={self.provider!r}, model={self.model!r})"

    # -- public ---------------------------------------------------------
    def call(self, prompt: str) -> str:
        """Send one prompt to the LLM and return its raw text reply."""
        if self.provider == "gemini":
            return self._call_gemini(prompt)
        return self._call_openai_compatible(prompt)

    # -- providers ------------------------------------------------------
    def _call_gemini(self, prompt: str) -> str:
        payload = {"contents": [{"parts": [{"text": prompt}]}]}
        try:
            resp = requests.post(
                GEMINI_URL,
                params={"key": self.api_key},
                json=payload,
                timeout=TIMEOUT,
            )
        except requests.RequestException as exc:
            raise RuntimeError(f"Could not reach Gemini API: {exc}") from exc

        if resp.status_code != 200:
            raise RuntimeError(
                f"Gemini API error ({resp.status_code}): {resp.text[:500]}. "
                "Check that GEMINI_API_KEY is correct and the free-tier "
                "quota is not exhausted."
            )
        try:
            data = resp.json()
            return data["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError, ValueError) as exc:
            raise RuntimeError(
                f"Unexpected Gemini response format: {resp.text[:500]}"
            ) from exc

    def _call_openai_compatible(self, prompt: str) -> str:
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2,
        }
        try:
            resp = requests.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
                timeout=TIMEOUT,
            )
        except requests.RequestException as exc:
            raise RuntimeError(
                f"Could not reach {self.provider} API: {exc}"
            ) from exc

        if resp.status_code != 200:
            raise RuntimeError(
                f"{self.provider} API error ({resp.status_code}): "
                f"{resp.text[:500]}"
            )
        try:
            return resp.json()["choices"][0]["message"]["content"]
        except (KeyError, IndexError, ValueError) as exc:
            raise RuntimeError(
                f"Unexpected {self.provider} response format: {resp.text[:500]}"
            ) from exc
