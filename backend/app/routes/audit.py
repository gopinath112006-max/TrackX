"""
Audit Trail Routes
==================
Expose the operational audit log (FR-16.2) for review and chain-of-custody
verification via the API.
"""

from fastapi import APIRouter

from app.services import audit_logger

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("")
def get_audit_log(limit: int = 500):
    """Return the most recent audit records (newest first)."""
    return {"records": audit_logger.read_audit_log(limit=limit)}


@router.get("/verify")
def verify_audit_chain():
    """Verify the tamper-evident hash chain is intact."""
    return audit_logger.verify_audit_chain()
