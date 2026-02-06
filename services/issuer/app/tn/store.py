"""TN Mapping Store for CRUD operations.

Sprint 42: Provides storage layer for TN-to-dossier mappings.
"""

import logging
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from app.db.models import TNMapping

log = logging.getLogger(__name__)


class TNMappingStore:
    """Store for TN mapping CRUD operations.

    Manages TN-to-dossier mappings scoped by organization.
    """

    def __init__(self, db: Session):
        """Initialize store with database session.

        Args:
            db: SQLAlchemy session
        """
        self.db = db

    def create(
        self,
        org_id: str,
        tn: str,
        dossier_said: str,
        identity_name: str,
        brand_name: Optional[str] = None,
        brand_logo_url: Optional[str] = None,
    ) -> TNMapping:
        """Create a new TN mapping.

        Args:
            org_id: Organization ID
            tn: E.164 telephone number
            dossier_said: Root credential SAID for the dossier
            identity_name: KERI identity name for signing
            brand_name: Cached brand name (optional)
            brand_logo_url: Cached logo URL (optional)

        Returns:
            Created TNMapping instance

        Raises:
            IntegrityError: If TN already exists for this org
        """
        mapping = TNMapping(
            id=str(uuid.uuid4()),
            tn=tn,
            organization_id=org_id,
            dossier_said=dossier_said,
            identity_name=identity_name,
            brand_name=brand_name,
            brand_logo_url=brand_logo_url,
            enabled=True,
        )
        self.db.add(mapping)
        self.db.commit()
        self.db.refresh(mapping)
        log.info(f"Created TN mapping: {tn} -> {dossier_said[:16]}...")
        return mapping

    def get(self, mapping_id: str) -> Optional[TNMapping]:
        """Get a TN mapping by ID.

        Args:
            mapping_id: Mapping UUID

        Returns:
            TNMapping if found, None otherwise
        """
        return self.db.query(TNMapping).filter(TNMapping.id == mapping_id).first()

    def get_by_tn(self, tn: str, org_id: Optional[str] = None) -> Optional[TNMapping]:
        """Get a TN mapping by telephone number.

        Args:
            tn: E.164 telephone number
            org_id: Optional org ID to scope the query

        Returns:
            TNMapping if found, None otherwise
        """
        query = self.db.query(TNMapping).filter(
            TNMapping.tn == tn,
            TNMapping.enabled == True,  # noqa: E712
        )
        if org_id:
            query = query.filter(TNMapping.organization_id == org_id)
        return query.first()

    def list_by_org(self, org_id: str) -> list[TNMapping]:
        """List all TN mappings for an organization.

        Args:
            org_id: Organization ID

        Returns:
            List of TNMapping instances
        """
        return (
            self.db.query(TNMapping)
            .filter(TNMapping.organization_id == org_id)
            .order_by(TNMapping.created_at.desc())
            .all()
        )

    def list_all(self) -> list[TNMapping]:
        """List all TN mappings (admin only).

        Returns:
            List of all TNMapping instances
        """
        return self.db.query(TNMapping).order_by(TNMapping.created_at.desc()).all()

    def update(
        self,
        mapping_id: str,
        dossier_said: Optional[str] = None,
        identity_name: Optional[str] = None,
        brand_name: Optional[str] = None,
        brand_logo_url: Optional[str] = None,
        enabled: Optional[bool] = None,
    ) -> Optional[TNMapping]:
        """Update a TN mapping.

        Args:
            mapping_id: Mapping UUID
            dossier_said: New dossier SAID (optional)
            identity_name: New identity name (optional)
            brand_name: New brand name (optional)
            brand_logo_url: New logo URL (optional)
            enabled: New enabled status (optional)

        Returns:
            Updated TNMapping if found, None otherwise
        """
        mapping = self.get(mapping_id)
        if not mapping:
            return None

        if dossier_said is not None:
            mapping.dossier_said = dossier_said
        if identity_name is not None:
            mapping.identity_name = identity_name
        if brand_name is not None:
            mapping.brand_name = brand_name
        if brand_logo_url is not None:
            mapping.brand_logo_url = brand_logo_url
        if enabled is not None:
            mapping.enabled = enabled

        mapping.updated_at = datetime.utcnow()
        self.db.commit()
        self.db.refresh(mapping)
        log.info(f"Updated TN mapping: {mapping.tn}")
        return mapping

    def delete(self, mapping_id: str) -> bool:
        """Delete a TN mapping.

        Args:
            mapping_id: Mapping UUID

        Returns:
            True if deleted, False if not found
        """
        mapping = self.get(mapping_id)
        if not mapping:
            return False

        tn = mapping.tn
        self.db.delete(mapping)
        self.db.commit()
        log.info(f"Deleted TN mapping: {tn}")
        return True

    def exists(self, tn: str, org_id: str) -> bool:
        """Check if a TN mapping exists for an org.

        Args:
            tn: E.164 telephone number
            org_id: Organization ID

        Returns:
            True if mapping exists
        """
        return (
            self.db.query(TNMapping)
            .filter(
                TNMapping.tn == tn,
                TNMapping.organization_id == org_id,
            )
            .first()
            is not None
        )
