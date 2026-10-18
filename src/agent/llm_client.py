"""LLM client interface supporting Gemini, OpenAI, Ollama, and Built-in Offline Engine."""
import os
import json
from typing import Optional, Dict, Any
from src.config import Config

class LLMClient:
    """Multi-provider LLM Client with automatic smart offline fallback."""

    def __init__(self, provider: Optional[str] = None):
        self.provider = (provider or Config.LLM_PROVIDER).lower()
        self.gemini_key = Config.GEMINI_API_KEY
        self.openai_key = Config.OPENAI_API_KEY
        self.ollama_url = Config.OLLAMA_BASE_URL
        self.model_name = Config.MODEL_NAME

        # Auto-detect if provider wasn't explicitly set but keys exist
        if self.provider == "offline":
            if self.gemini_key:
                self.provider = "gemini"
            elif self.openai_key:
                self.provider = "openai"

    def generate(self, system_prompt: str, prompt: str) -> str:
        """Dispatches prompt to the configured LLM provider or returns offline fallback."""
        if self.provider == "gemini" and self.gemini_key:
            return self._call_gemini(system_prompt, prompt)
        elif self.provider == "openai" and self.openai_key:
            return self._call_openai(system_prompt, prompt)
        elif self.provider == "ollama":
            return self._call_ollama(system_prompt, prompt)
        else:
            return ""

    def _call_gemini(self, system_prompt: str, prompt: str) -> str:
        try:
            from google import genai
            client = genai.Client(api_key=self.gemini_key)
            response = client.models.generate_content(
                model=self.model_name or "gemini-1.5-flash",
                contents=f"{system_prompt}\n\n{prompt}"
            )
            return response.text
        except Exception as e:
            # Fallback gracefully
            return f"[Gemini Error: {e}]"

    def _call_openai(self, system_prompt: str, prompt: str) -> str:
        try:
            from openai import OpenAI
            client = OpenAI(api_key=self.openai_key)
            response = client.chat.completions.create(
                model=self.model_name or "gpt-4o-mini",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2
            )
            return response.choices[0].message.content or ""
        except Exception as e:
            return f"[OpenAI Error: {e}]"

    def _call_ollama(self, system_prompt: str, prompt: str) -> str:
        try:
            import requests
            resp = requests.post(
                f"{self.ollama_url}/api/generate",
                json={
                    "model": self.model_name or "llama3",
                    "prompt": f"{system_prompt}\n\n{prompt}",
                    "stream": False
                },
                timeout=60
            )
            if resp.status_code == 200:
                return resp.json().get("response", "")
            return f"[Ollama Error {resp.status_code}: {resp.text}]"
        except Exception as e:
            return f"[Ollama Connection Error: {e}]"
