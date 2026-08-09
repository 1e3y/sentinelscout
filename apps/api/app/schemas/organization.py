from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class OrganizationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    clerk_org_id: str
    name: str
    role: str
    created_at: datetime


class OrganizationDetailResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    clerk_org_id: str
    name: str
    role: str
    created_at: datetime
