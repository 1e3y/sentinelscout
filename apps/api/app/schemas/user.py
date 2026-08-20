from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    clerk_user_id: str
    email: EmailStr
    name: str | None
    created_at: datetime
    active_organization_id: UUID | None = None
    active_organization_role: str | None = None
