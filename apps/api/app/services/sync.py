from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Organization, OrganizationMembership, User
from app.services.clerk import ClerkDirectory, ClerkOrgMembership, ClerkUserInfo


def upsert_user(db: Session, info: ClerkUserInfo) -> User:
    user = db.scalar(select(User).where(User.clerk_user_id == info.clerk_user_id))
    if user is None:
        user = User(
            clerk_user_id=info.clerk_user_id,
            email=info.email,
            email_verified=bool(info.email_verified),
            name=info.name,
        )
        db.add(user)
    else:
        user.email = info.email
        user.email_verified = bool(info.email_verified)
        user.name = info.name
    db.flush()
    return user


def sync_memberships(
    db: Session,
    user: User,
    memberships: list[ClerkOrgMembership],
) -> list[OrganizationMembership]:
    """Replace persisted memberships for this user with Clerk's current set."""
    desired_org_ids = {m.clerk_org_id for m in memberships}
    existing = list(
        db.scalars(
            select(OrganizationMembership).where(OrganizationMembership.user_id == user.id)
        ).all()
    )

    # Upsert orgs + memberships from Clerk
    result: list[OrganizationMembership] = []
    for membership in memberships:
        org = db.scalar(
            select(Organization).where(Organization.clerk_org_id == membership.clerk_org_id)
        )
        if org is None:
            org = Organization(clerk_org_id=membership.clerk_org_id, name=membership.org_name)
            db.add(org)
            db.flush()
        else:
            org.name = membership.org_name

        row = db.scalar(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == org.id,
                OrganizationMembership.user_id == user.id,
            )
        )
        if row is None:
            row = OrganizationMembership(
                organization_id=org.id,
                user_id=user.id,
                role=membership.role,
            )
            db.add(row)
        else:
            row.role = membership.role
        db.flush()
        result.append(row)

    # Remove memberships that no longer exist in Clerk
    for row in existing:
        org = db.get(Organization, row.organization_id)
        if org is None or org.clerk_org_id not in desired_org_ids:
            db.delete(row)

    db.flush()
    return result


def sync_user_from_clerk(db: Session, directory: ClerkDirectory, clerk_user_id: str) -> User:
    info = directory.get_user(clerk_user_id)
    user = upsert_user(db, info)
    memberships = directory.list_organization_memberships(clerk_user_id)
    sync_memberships(db, user, memberships)
    db.commit()
    db.refresh(user)
    return user
