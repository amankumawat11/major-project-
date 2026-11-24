from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime

class ChatMessageRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=2000)
    session_id: Optional[str] = "default"
    scan_id: Optional[str] = None

class ChatMessageResponse(BaseModel):
    role: str = "assistant"
    content: str
    session_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

class AIExplainRequest(BaseModel):
    vuln_id: str
    title: str
    category: str
    severity: str
    description: str
    evidence: Optional[str] = None
    affected_url: str
