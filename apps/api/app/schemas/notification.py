from pydantic import BaseModel, ConfigDict, Field


class NotificationMemberResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: str
    name: str | None = None
    email: str
    email_verified: bool


class NotificationSettingsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    organization_id: str
    email_enabled: bool
    email_min_priority: str
    recipients: list[NotificationMemberResponse] = Field(default_factory=list)
    members: list[NotificationMemberResponse] = Field(default_factory=list)
    can_manage: bool


class NotificationSettingsUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email_enabled: bool
    email_min_priority: str = "medium"
    recipient_user_ids: list[str] = Field(default_factory=list)
