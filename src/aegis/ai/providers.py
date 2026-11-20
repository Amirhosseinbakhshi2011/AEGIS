"""Optional external AI provider adapters.

Both adapters implement the small ``AIProvider`` protocol and are used only
when explicitly configured. Any failure falls back to the local analyst.
"""

from __future__ import annotations

import httpx


class OpenAIProvider:
    def __init__(self, api_key: str, model: str) -> None:
        self.api_key = api_key
        self.model = model

    async def analyze(self, prompt: str, context: dict[str, object]) -> str:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "model": self.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.2,
                },
            )
            response.raise_for_status()
            data = response.json()
            return str(data["choices"][0]["message"]["content"])


class AnthropicProvider:
    def __init__(self, api_key: str, model: str = "claude-3-5-haiku-latest") -> None:
        self.api_key = api_key
        self.model = model

    async def analyze(self, prompt: str, context: dict[str, object]) -> str:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                },
                json={
                    "model": self.model,
                    "max_tokens": 1000,
                    "messages": [{"role": "user", "content": prompt}],
                },
            )
            response.raise_for_status()
            data = response.json()
            return "".join(block.get("text", "") for block in data.get("content", []))
