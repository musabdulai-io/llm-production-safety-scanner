# backend/app/features/scanner/attacks/base.py
"""Base class for attack modules."""

from abc import ABC, abstractmethod
from typing import Optional

import httpx

from ..models import AttackResult


class AttackModule(ABC):
    """Abstract base class for attack modules."""

    name: str
    description: str

    @abstractmethod
    async def execute(
        self,
        client: httpx.AsyncClient,
        target_url: str,
        headers: Optional[dict] = None,
    ) -> AttackResult:
        """
        Execute the attack and return results.

        Args:
            client: Async HTTP client for making requests
            target_url: Target LLM/RAG endpoint URL
            headers: Optional custom headers for requests

        Returns:
            AttackResult containing findings and evidence
        """
        pass
