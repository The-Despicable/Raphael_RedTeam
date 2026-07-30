from pydantic import BaseModel
from typing import Any, Optional


class MCPRequest(BaseModel):
    method: str
    params: Optional[dict] = None
    id: Optional[int] = None


class MCPResponse(BaseModel):
    result: Optional[Any] = None
    error: Optional[dict] = None
    id: Optional[int] = None


class ToolSchema(BaseModel):
    name: str
    description: str
    category: str
    input_schema: dict
    output_schema: Optional[dict] = None


class ToolListResult(BaseModel):
    tools: list[ToolSchema]


class ToolCallParams(BaseModel):
    name: str
    arguments: dict


class ToolCallResult(BaseModel):
    content: list[dict]
    isError: bool = False


class ResourceSchema(BaseModel):
    uri: str
    name: str
    description: Optional[str] = None
    mimeType: str = "application/json"


class PromptSchema(BaseModel):
    name: str
    description: Optional[str] = None
    arguments: list[dict] = []
