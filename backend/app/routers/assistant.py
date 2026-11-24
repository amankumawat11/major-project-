from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.models.scan import Scan
from app.models.chat import ChatMessage
from app.schemas.chat import ChatMessageRequest, ChatMessageResponse, AIExplainRequest
from app.services.ai_explainer import ask_security_assistant, enrich_vulnerability_with_ai

router = APIRouter(prefix="/api/ai", tags=["AI Assistant"])

@router.post("/explain")
def explain_vulnerability(req: AIExplainRequest):
    finding_dict = {
        "vuln_id": req.vuln_id,
        "title": req.title,
        "severity": req.severity,
        "category": req.category,
        "description": req.description,
        "evidence": req.evidence,
        "affected_url": req.affected_url
    }
    enriched = enrich_vulnerability_with_ai(finding_dict)
    return enriched

@router.post("/chat", response_model=ChatMessageResponse)
def chat_with_assistant(req: ChatMessageRequest, db: Session = Depends(get_db)):
    # 1. Fetch scan context if scan_id provided
    scan_context = None
    if req.scan_id:
        scan = db.query(Scan).filter(Scan.scan_id == req.scan_id).first()
        if scan:
            vuln_summary = "\n".join([
                f"- {v.title} (Severity: {v.severity}, Category: {v.category}): {v.description}"
                for v in scan.vulnerabilities[:5]
            ])
            scan_context = (
                f"Website: {scan.target_domain} ({scan.target_url})\n"
                f"Security Score: {scan.security_score}/100 (Risk: {scan.risk_level})\n"
                f"Vulnerabilities Detected:\n{vuln_summary}"
            )

    # 2. Save user message
    user_msg = ChatMessage(
        session_id=req.session_id or "default",
        role="user",
        content=req.message
    )
    db.add(user_msg)
    db.commit()

    # 3. Call AI assistant service
    reply_text = ask_security_assistant(
        message=req.message,
        session_id=req.session_id or "default",
        scan_context=scan_context
    )

    # 4. Save assistant response
    assistant_msg = ChatMessage(
        session_id=req.session_id or "default",
        role="assistant",
        content=reply_text
    )
    db.add(assistant_msg)
    db.commit()

    return ChatMessageResponse(
        role="assistant",
        content=reply_text,
        session_id=req.session_id or "default"
    )

@router.get("/chat/{session_id}", response_model=List[ChatMessageResponse])
def get_chat_history(session_id: str, db: Session = Depends(get_db)):
    messages = db.query(ChatMessage).filter(ChatMessage.session_id == session_id).order_by(ChatMessage.created_at.asc()).all()
    return [
        ChatMessageResponse(
            role=m.role,
            content=m.content,
            session_id=m.session_id,
            created_at=m.created_at
        )
        for m in messages
    ]
