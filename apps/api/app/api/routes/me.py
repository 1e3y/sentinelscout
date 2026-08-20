from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.deps import AuthContext, get_auth_context
from app.schemas.user import UserResponse

router = APIRouter(prefix="/v1", tags=["me"])


@router.get("/me", response_model=UserResponse)
def get_me(auth: Annotated[AuthContext, Depends(get_auth_context)]) -> UserResponse:
    actor = auth.org_actor()
    return UserResponse(
        id=auth.user.id,
        clerk_user_id=auth.user.clerk_user_id,
        email=auth.user.email,
        name=auth.user.name,
        created_at=auth.user.created_at,
        active_organization_id=auth.active_organization.id if auth.active_organization else None,
        active_organization_role=actor.normalized_role if actor is not None else None,
    )
