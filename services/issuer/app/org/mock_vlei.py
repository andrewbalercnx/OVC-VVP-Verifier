"""Mock vLEI infrastructure for development and testing.

This module provides a mock GLEIF and QVI credential chain for development
and testing purposes. It creates:

1. mock-gleif identity - Simulates the GLEIF root authority
2. mock-gleif-registry - Registry for GLEIF-issued credentials
3. mock-qvi identity - Simulates a Qualified vLEI Issuer
4. mock-qvi-registry - Registry for QVI-issued credentials
5. QVI credential from mock-gleif to mock-qvi

When organizations are created, they receive Legal Entity credentials
from mock-qvi, establishing a valid (mock) credential chain.

IMPORTANT: This infrastructure is for development/testing only.
Production deployments should use real GLEIF and QVI credentials.
"""

import logging
from dataclasses import dataclass
from typing import Optional

from app.config import MOCK_GLEIF_NAME, MOCK_QVI_NAME, MOCK_VLEI_ENABLED
from app.db.session import get_db_session
from app.db.models import MockVLEIState as MockVLEIStateModel

log = logging.getLogger(__name__)

# Schema SAIDs (from vLEI Ecosystem Governance Framework)
QVI_SCHEMA_SAID = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
LEGAL_ENTITY_SCHEMA_SAID = "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY"


@dataclass
class MockVLEIState:
    """State of mock vLEI infrastructure."""

    gleif_aid: str
    gleif_registry_key: str
    qvi_aid: str
    qvi_credential_said: str
    qvi_registry_key: str
    initialized: bool = True


# Module-level singleton
_mock_vlei_manager: Optional["MockVLEIManager"] = None


def get_mock_vlei_manager() -> "MockVLEIManager":
    """Get or create the mock vLEI manager singleton."""
    global _mock_vlei_manager
    if _mock_vlei_manager is None:
        _mock_vlei_manager = MockVLEIManager()
    return _mock_vlei_manager


class MockVLEIManager:
    """Manages mock GLEIF and QVI identities for development/testing.

    Creates a pseudo root-of-trust:
    - mock-gleif identity with registry
    - mock-qvi identity with QVI credential from mock-gleif

    Organizations created via the API receive Legal Entity credentials
    from mock-qvi, establishing a valid (mock) credential chain.
    """

    def __init__(self):
        self._state: Optional[MockVLEIState] = None

    @property
    def state(self) -> Optional[MockVLEIState]:
        """Get current mock vLEI state (None if not initialized)."""
        return self._state

    @property
    def is_initialized(self) -> bool:
        """Check if mock vLEI infrastructure is initialized."""
        return self._state is not None and self._state.initialized

    async def initialize(self) -> MockVLEIState:
        """Initialize mock GLEIF and QVI identities on startup.

        This method is idempotent - it checks for existing state in the
        database and KERI stores before creating new infrastructure.

        Returns:
            MockVLEIState with initialized infrastructure details

        Raises:
            RuntimeError: If mock vLEI is disabled via config
        """
        if not MOCK_VLEI_ENABLED:
            raise RuntimeError("Mock vLEI is disabled (VVP_MOCK_VLEI_ENABLED=false)")

        # Check for persisted state in database
        persisted_state = self._load_persisted_state()
        if persisted_state:
            log.info("Restored mock vLEI state from database")
            self._state = persisted_state
            return self._state

        # Import here to avoid circular imports
        from app.keri.identity import get_identity_manager
        from app.keri.registry import get_registry_manager
        from app.keri.issuer import get_credential_issuer

        identity_mgr = await get_identity_manager()
        registry_mgr = await get_registry_manager()
        issuer = await get_credential_issuer()

        log.info("Initializing mock vLEI infrastructure...")

        # 1. Create or get mock-gleif identity
        gleif_info = await identity_mgr.get_identity_by_name(MOCK_GLEIF_NAME)
        if gleif_info is None:
            gleif_info = await identity_mgr.create_identity(
                name=MOCK_GLEIF_NAME,
                transferable=True,
            )
            log.info(f"Created mock GLEIF identity: {gleif_info.aid[:16]}...")
        else:
            log.info(f"Found existing mock GLEIF identity: {gleif_info.aid[:16]}...")

        # 2. Create or get mock-gleif registry
        gleif_registry_name = f"{MOCK_GLEIF_NAME}-registry"
        gleif_registry = registry_mgr.regery.registryByName(gleif_registry_name)
        if gleif_registry is None:
            gleif_registry_info = await registry_mgr.create_registry(
                name=gleif_registry_name,
                issuer_aid=gleif_info.aid,
            )
            gleif_registry_key = gleif_registry_info.registry_key
            log.info(f"Created mock GLEIF registry: {gleif_registry_key[:16]}...")
        else:
            gleif_registry_key = gleif_registry.regk
            log.info(f"Found existing mock GLEIF registry: {gleif_registry_key[:16]}...")

        # 3. Create or get mock-qvi identity
        qvi_info = await identity_mgr.get_identity_by_name(MOCK_QVI_NAME)
        if qvi_info is None:
            qvi_info = await identity_mgr.create_identity(
                name=MOCK_QVI_NAME,
                transferable=True,
            )
            log.info(f"Created mock QVI identity: {qvi_info.aid[:16]}...")
        else:
            log.info(f"Found existing mock QVI identity: {qvi_info.aid[:16]}...")

        # 4. Create or get mock-qvi registry
        qvi_registry_name = f"{MOCK_QVI_NAME}-registry"
        qvi_registry = registry_mgr.regery.registryByName(qvi_registry_name)
        if qvi_registry is None:
            qvi_registry_info = await registry_mgr.create_registry(
                name=qvi_registry_name,
                issuer_aid=qvi_info.aid,
            )
            qvi_registry_key = qvi_registry_info.registry_key
            log.info(f"Created mock QVI registry: {qvi_registry_key[:16]}...")
        else:
            qvi_registry_key = qvi_registry.regk
            log.info(f"Found existing mock QVI registry: {qvi_registry_key[:16]}...")

        # 5. Issue QVI credential from mock-gleif to mock-qvi (if not exists)
        qvi_cred_said = await self._get_or_issue_qvi_credential(
            issuer=issuer,
            gleif_registry_name=gleif_registry_name,
            qvi_aid=qvi_info.aid,
        )

        # 6. Persist state to database
        self._state = MockVLEIState(
            gleif_aid=gleif_info.aid,
            gleif_registry_key=gleif_registry_key,
            qvi_aid=qvi_info.aid,
            qvi_credential_said=qvi_cred_said,
            qvi_registry_key=qvi_registry_key,
        )
        self._persist_state(self._state)

        log.info("Mock vLEI infrastructure initialized successfully")
        return self._state

    async def _get_or_issue_qvi_credential(
        self,
        issuer,
        gleif_registry_name: str,
        qvi_aid: str,
    ) -> str:
        """Get existing QVI credential SAID or issue a new one.

        Args:
            issuer: CredentialIssuer instance
            gleif_registry_name: Name of the GLEIF registry
            qvi_aid: AID of the mock QVI

        Returns:
            SAID of the QVI credential
        """
        # Check if we already have a QVI credential for this QVI
        # We look for credentials in the registry that match the QVI schema
        # and have the QVI as recipient
        from app.keri.registry import get_registry_manager

        registry_mgr = await get_registry_manager()
        reger = registry_mgr.regery.reger

        # Scan issued credentials for existing QVI credential
        for said, creder in reger.creds.getItemIter():
            # Check if this is a QVI credential issued to our mock-qvi
            if hasattr(creder, "schema") and creder.schema == QVI_SCHEMA_SAID:
                # Check recipient
                attrib = creder.attrib if hasattr(creder, "attrib") else {}
                if attrib.get("i") == qvi_aid:
                    log.info(f"Found existing QVI credential: {creder.said[:16]}...")
                    return creder.said

        # No existing credential found, issue a new one
        log.info("Issuing new QVI credential from mock-gleif to mock-qvi...")

        # QVI credential attributes per vLEI Governance Framework
        qvi_attributes = {
            "i": qvi_aid,  # Issuee AID
            "LEI": "5493MOCK0QVI0000000",  # Pseudo-LEI for mock QVI
        }

        cred_info, _ = await issuer.issue_credential(
            registry_name=gleif_registry_name,
            schema_said=QVI_SCHEMA_SAID,
            attributes=qvi_attributes,
            recipient_aid=qvi_aid,
        )

        log.info(f"Issued QVI credential: {cred_info.said[:16]}...")
        return cred_info.said

    async def issue_le_credential(
        self,
        org_name: str,
        org_aid: str,
        pseudo_lei: str,
    ) -> str:
        """Issue a Legal Entity credential from mock-qvi to an organization.

        Args:
            org_name: Organization name
            org_aid: Organization's KERI AID
            pseudo_lei: Organization's pseudo-LEI

        Returns:
            SAID of the issued Legal Entity credential

        Raises:
            RuntimeError: If mock vLEI is not initialized
        """
        if self._state is None:
            raise RuntimeError("Mock vLEI not initialized")

        from app.keri.issuer import get_credential_issuer

        issuer = await get_credential_issuer()

        # Legal Entity credential attributes per vLEI Governance Framework
        le_attributes = {
            "i": org_aid,  # Issuee AID
            "LEI": pseudo_lei,
        }

        # Edge to QVI credential for chain verification
        edges = {
            "qvi": {
                "n": self._state.qvi_credential_said,
                "s": QVI_SCHEMA_SAID,
            }
        }

        qvi_registry_name = f"{MOCK_QVI_NAME}-registry"
        cred_info, _ = await issuer.issue_credential(
            registry_name=qvi_registry_name,
            schema_said=LEGAL_ENTITY_SCHEMA_SAID,
            attributes=le_attributes,
            recipient_aid=org_aid,
            edges=edges,
        )

        log.info(f"Issued LE credential for {org_name}: {cred_info.said[:16]}...")
        return cred_info.said

    def _load_persisted_state(self) -> Optional[MockVLEIState]:
        """Load persisted mock vLEI state from database."""
        try:
            with get_db_session() as db:
                state_record = db.query(MockVLEIStateModel).first()
                if state_record:
                    return MockVLEIState(
                        gleif_aid=state_record.gleif_aid,
                        gleif_registry_key=state_record.gleif_registry_key,
                        qvi_aid=state_record.qvi_aid,
                        qvi_credential_said=state_record.qvi_credential_said,
                        qvi_registry_key=state_record.qvi_registry_key,
                    )
        except Exception as e:
            # Database may not be initialized yet
            log.debug(f"Could not load persisted mock vLEI state: {e}")
        return None

    def _persist_state(self, state: MockVLEIState) -> None:
        """Persist mock vLEI state to database."""
        try:
            with get_db_session() as db:
                # Delete any existing state (should be at most one row)
                db.query(MockVLEIStateModel).delete()

                # Insert new state
                state_record = MockVLEIStateModel(
                    gleif_aid=state.gleif_aid,
                    gleif_registry_key=state.gleif_registry_key,
                    qvi_aid=state.qvi_aid,
                    qvi_credential_said=state.qvi_credential_said,
                    qvi_registry_key=state.qvi_registry_key,
                )
                db.add(state_record)
                log.info("Persisted mock vLEI state to database")
        except Exception as e:
            log.warning(f"Could not persist mock vLEI state: {e}")
