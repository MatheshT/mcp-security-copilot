from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class ToolRequest(BaseModel):
    query: str
    metadata: Dict[str, Any] = {}


class ToolResponse(BaseModel):
    tool_name: str
    status: str
    data: Dict[str, Any]
    details: Optional[str] = None


class BaseMCPServer(ABC):
    name: str
    description: str
    supported_features: List[str] = []

    def __init__(self) -> None:
        if not hasattr(self, 'name') or not self.name:
            raise ValueError('Tool server must define a name')

    def handle_request(self, request: ToolRequest) -> ToolResponse:
        """
        Default handler for tool requests. Concrete tool servers should
        override this method. Providing a default implementation avoids
        abstract-class instantiation errors during client registration.
        """
        return ToolResponse(
            tool_name=getattr(self, 'name', 'unknown'),
            status='error',
            data={},
            details='handle_request not implemented for this tool',
        )

    def start(self) -> None:
        """Optional hook for registering this tool with an external MCP runtime."""
        return None
