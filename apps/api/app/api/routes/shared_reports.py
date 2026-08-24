from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.services.rate_limit import (
    ACTION_SHARED_REPORT_COARSE,
    ACTION_SHARED_REPORT_USE,
    coarse_share_partition,
    enforce_anonymous_rate_limit,
)
from app.services.reports.share import (
    NO_STORE_HEADERS,
    export_shared_report_pdf,
    read_external_share_secret,
    resolve_shared_report,
)

router = APIRouter(prefix="/v1/shared-reports", tags=["shared-reports"])


def _commit_rate_limits(db: Session) -> None:
    try:
        db.commit()
    except Exception:
        db.rollback()


@router.post("/{share_id}/resolve")
async def resolve_shared_report_endpoint(
    share_id: UUID,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
) -> JSONResponse:
    enforce_anonymous_rate_limit(
        db, action=ACTION_SHARED_REPORT_COARSE, bucket=coarse_share_partition(share_id)
    )
    try:
        secret = await read_external_share_secret(request)
        payload = resolve_shared_report(db, share_id=share_id, secret=secret)
        enforce_anonymous_rate_limit(
            db, action=ACTION_SHARED_REPORT_USE, bucket=str(share_id)
        )
        _commit_rate_limits(db)
        return JSONResponse(content=payload, headers=dict(NO_STORE_HEADERS))
    except Exception:
        _commit_rate_limits(db)
        raise


@router.post("/{share_id}/pdf")
async def export_shared_report_pdf_endpoint(
    share_id: UUID,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
) -> Response:
    enforce_anonymous_rate_limit(
        db, action=ACTION_SHARED_REPORT_COARSE, bucket=coarse_share_partition(share_id)
    )
    try:
        secret = await read_external_share_secret(request)
        pdf_bytes, filename = export_shared_report_pdf(
            db, share_id=share_id, secret=secret
        )
        enforce_anonymous_rate_limit(
            db, action=ACTION_SHARED_REPORT_USE, bucket=str(share_id)
        )
        _commit_rate_limits(db)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                **NO_STORE_HEADERS,
                "Content-Disposition": f'attachment; filename="{filename}"',
            },
        )
    except Exception:
        _commit_rate_limits(db)
        raise
