"""KERI credential registry management for VVP Issuer.

Wraps keripy's Regery to provide TEL (Transaction Event Log) registry
lifecycle management for ACDC credential issuance tracking.
"""
import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from keri.core import coring, eventing, serdering
from keri.db.dbing import dgKey, snKey
from keri.vdr.credentialing import Regery
from keri.vdr.viring import Reger

from app.keri.identity import get_identity_manager

log = logging.getLogger(__name__)


@dataclass
class RegistryInfo:
    """Information about a credential registry."""

    registry_key: str  # Registry prefix (regk)
    name: str  # Human-readable name
    issuer_aid: str  # Issuer identity AID
    created_at: str  # ISO8601 timestamp
    sequence_number: int  # Current TEL sequence
    no_backers: bool  # Whether using TEL-specific backers


class CredentialRegistryManager:
    """Manages KERI credential registries for the issuer service.

    Wraps keripy's Regery to provide:
    - Registry creation with configurable backers
    - TEL event serialization for witness publishing
    - Registry lookup by key or name
    - Persistence across restarts

    The manager shares the Habery instance from IssuerIdentityManager,
    as Regery requires a Habery for identity context.
    """

    def __init__(self, temp: bool = False):
        """Initialize registry manager.

        Args:
            temp: If True, use temporary storage (for testing).

        Note: Call initialize() to complete setup after construction.
        """
        self._regery: Optional[Regery] = None
        self._lock = asyncio.Lock()
        self._initialized = False
        self._temp = temp

    async def initialize(self) -> None:
        """Initialize the Regery with shared Habery.

        Must be called after IssuerIdentityManager is initialized.
        """
        async with self._lock:
            if self._initialized:
                return

            # Get shared Habery from identity manager
            identity_mgr = await get_identity_manager()
            hby = identity_mgr.habery

            # Use identity manager's temp mode if not explicitly set
            # This ensures the Regery uses the same storage mode as the Habery
            temp_mode = self._temp or identity_mgr.temp

            # Create Reger with the same headDirPath as the Habery's database.
            # This ensures TEL events are stored in the same location as KEL events.
            # IMPORTANT: db=hby.db enables the read-through tever cache (rbdict).
            # Without it, reger.tevers is a plain dict and Tever objects are never
            # auto-loaded from the persisted RegStateRecord entries in LMDB,
            # causing KeyError when accessing registry.tever after restart.
            reger = Reger(
                name=hby.name,
                headDirPath=hby.db.headDirPath,
                db=hby.db,
                temp=temp_mode,
                reopen=True,
            )

            # Create Regery sharing the Habery and our Reger
            self._regery = Regery(
                hby=hby,
                name=hby.name,
                reger=reger,
                temp=temp_mode,
            )

            log.info(f"Regery initialized with {len(self._regery.regs)} existing registries")

            # Ensure tevers are loaded for all existing registries.
            # With db=hby.db, reger.tevers is an rbdict that auto-loads
            # from persisted RegStateRecord.  For registries without state
            # records (created before this fix), we bootstrap from raw TEL.
            self._ensure_tevers_loaded()

            self._initialized = True

    def _ensure_tevers_loaded(self) -> None:
        """Ensure Tever objects exist for all loaded registries.

        The rbdict read-through cache (enabled by db=hby.db in Reger)
        auto-loads Tevers from persisted RegStateRecord entries.  However,
        if the Reger was previously created without ``db``, those state
        records were never written.  In that case, we reconstruct Tevers
        from the raw TEL data (VCP event + anchor) that ``Tever.logEvent``
        wrote to LMDB during the original ``create_registry()`` call.
        """
        reger = self._regery.reger
        tvy = self._regery.tvy
        cached = 0
        bootstrapped = 0
        failed = 0

        for regk, registry in list(self._regery.regs.items()):
            # Check if tever already loadable (via rbdict state cache)
            if regk in reger.tevers:
                cached += 1
                continue

            # Not in cache — try to reconstruct from raw TEL data
            try:
                pre = regk.encode("utf-8") if isinstance(regk, str) else regk

                # Get VCP digest at TEL sequence 0 (inception)
                dig = reger.getTel(snKey(pre, 0))
                if dig is None:
                    log.warning(f"Registry {registry.name} ({regk[:16]}...): "
                                "no TEL entry at sn=0, skipping")
                    failed += 1
                    continue

                # Get VCP event bytes
                vcp_raw = reger.getTvt(dgKey(pre, bytes(dig)))
                if vcp_raw is None:
                    log.warning(f"Registry {registry.name} ({regk[:16]}...): "
                                "no TVT entry for VCP, skipping")
                    failed += 1
                    continue

                # Get anchor (seqner || saider bytes)
                anc = reger.getAnc(dgKey(pre, bytes(dig)))
                if anc is None:
                    log.warning(f"Registry {registry.name} ({regk[:16]}...): "
                                "no anchor entry, skipping")
                    failed += 1
                    continue

                # Parse VCP serder and anchor components
                vcp_serder = serdering.SerderKERI(raw=bytes(vcp_raw))
                ancb = bytearray(anc)
                seqner = coring.Seqner(qb64b=ancb, strip=True)
                saider = coring.Saider(qb64b=ancb, strip=True)

                # Process through Tevery — creates Tever and (with rbdict)
                # persists RegStateRecord to reger.states for future loads
                tvy.processEvent(
                    serder=vcp_serder,
                    seqner=seqner,
                    saider=saider,
                )
                bootstrapped += 1
                log.info(f"Bootstrapped tever for {registry.name} ({regk[:16]}...)")

            except Exception as e:
                failed += 1
                log.warning(f"Failed to bootstrap tever for {registry.name} "
                            f"({regk[:16]}...): {e}")

        parts = []
        if cached:
            parts.append(f"{cached} from state cache")
        if bootstrapped:
            parts.append(f"{bootstrapped} bootstrapped from TEL")
        if failed:
            parts.append(f"{failed} failed")
        if parts:
            log.info(f"Tever loading: {', '.join(parts)}")

    async def close(self) -> None:
        """Close the Regery and release resources."""
        async with self._lock:
            if self._regery is not None:
                self._regery.close()
                self._regery = None
                self._initialized = False
                log.info("Regery closed")

    @property
    def regery(self) -> Regery:
        """Get the Regery instance (raises if not initialized)."""
        if self._regery is None:
            raise RuntimeError("CredentialRegistryManager not initialized")
        return self._regery

    async def create_registry(
        self,
        name: str,
        issuer_aid: str,
        no_backers: bool = True,
    ) -> RegistryInfo:
        """Create a new credential registry.

        Args:
            name: Human-readable name for the registry
            issuer_aid: AID of the issuing identity
            no_backers: If True (default), no TEL-specific backers;
                        TEL events anchor to issuer's KEL witnesses

        Returns:
            RegistryInfo with created registry details

        Raises:
            ValueError: If registry with name already exists or issuer not found
        """
        async with self._lock:
            # Check for existing registry with same name
            if self.regery.registryByName(name) is not None:
                raise ValueError(f"Registry '{name}' already exists")

            # Verify issuer identity exists
            identity_mgr = await get_identity_manager()
            issuer_info = await identity_mgr.get_identity(issuer_aid)
            if issuer_info is None:
                raise ValueError(f"Issuer identity not found: {issuer_aid}")

            # Create registry using Regery
            # makeRegistry creates TEL inception event (vcp)
            registry = self.regery.makeRegistry(
                name=name,
                prefix=issuer_aid,
                noBackers=no_backers,
            )

            # Anchor the registry inception (vcp) to the issuer's KEL
            # This creates a seal in the KEL that points to the TEL inception
            # Without this anchor, the Tevery won't process the VCP and tever won't be created
            hab = registry.hab
            rseal = eventing.SealEvent(registry.vcp.pre, registry.vcp.snh, registry.vcp.said)
            anc = hab.interact(data=[dict(i=rseal.i, s=rseal.s, d=rseal.d)])

            # Get anchor reference from the KEL event we just created
            seqner = coring.Seqner(sn=hab.kever.sn)
            saider = coring.Saider(qb64=hab.kever.serder.said)

            # Store the anchor in the reger database
            registry.anchorMsg(
                pre=registry.regk,
                regd=registry.regd,
                seqner=seqner,
                saider=saider,
            )

            # Re-process the VCP event with the anchor reference
            # This will create the tever in reger.tevers
            # We call tvy.processEvent directly because Registry.processEvent
            # doesn't pass seqner/saider to the tevery
            self.regery.tvy.processEvent(
                serder=registry.vcp,
                seqner=seqner,
                saider=saider,
            )

            log.info(f"Created registry: {name} ({registry.regk[:16]}...) for issuer {issuer_aid[:16]}...")

            # Get sequence number safely - tever may not be processed yet
            try:
                seq_num = registry.regi
            except (KeyError, AttributeError):
                seq_num = 0

            return RegistryInfo(
                registry_key=registry.regk,
                name=name,
                issuer_aid=issuer_aid,
                created_at=datetime.now(timezone.utc).isoformat(),
                sequence_number=seq_num,
                no_backers=no_backers,
            )

    async def get_registry(self, registry_key: str) -> Optional[RegistryInfo]:
        """Get registry info by registry key."""
        async with self._lock:
            registry = self.regery.regs.get(registry_key)
            if registry is None:
                return None

            # Get issuer AID from hab safely
            try:
                issuer_aid = registry.hab.pre if registry.hab else ""
            except (KeyError, AttributeError):
                issuer_aid = ""

            # Get sequence number safely - tever may not be processed yet
            try:
                seq_num = registry.regi
            except (KeyError, AttributeError):
                seq_num = 0

            # Get noBackers safely - tever may not be processed yet
            try:
                no_backers = registry.noBackers
            except (KeyError, AttributeError):
                no_backers = True

            return RegistryInfo(
                registry_key=registry.regk,
                name=registry.name,
                issuer_aid=issuer_aid,
                created_at="",  # Not stored in keripy
                sequence_number=seq_num,
                no_backers=no_backers,
            )

    async def get_registry_by_name(self, name: str) -> Optional[RegistryInfo]:
        """Get registry info by name."""
        async with self._lock:
            registry = self.regery.registryByName(name)
            if registry is None:
                return None

            # Get issuer AID from hab safely
            try:
                issuer_aid = registry.hab.pre if registry.hab else ""
            except (KeyError, AttributeError):
                issuer_aid = ""

            # Get sequence number safely - tever may not be processed yet
            try:
                seq_num = registry.regi
            except (KeyError, AttributeError):
                seq_num = 0

            # Get noBackers safely - tever may not be processed yet
            try:
                no_backers = registry.noBackers
            except (KeyError, AttributeError):
                no_backers = True

            return RegistryInfo(
                registry_key=registry.regk,
                name=registry.name,
                issuer_aid=issuer_aid,
                created_at="",
                sequence_number=seq_num,
                no_backers=no_backers,
            )

    async def list_registries(self) -> list[RegistryInfo]:
        """List all managed registries."""
        async with self._lock:
            registries = []
            for regk, registry in self.regery.regs.items():
                # Get issuer AID from hab safely
                try:
                    issuer_aid = registry.hab.pre if registry.hab else ""
                except (KeyError, AttributeError):
                    issuer_aid = ""

                # Get sequence number safely - tever may not be processed yet
                try:
                    seq_num = registry.regi
                except (KeyError, AttributeError):
                    seq_num = 0

                # Get noBackers safely - tever may not be processed yet
                try:
                    no_backers = registry.noBackers
                except (KeyError, AttributeError):
                    no_backers = True

                info = RegistryInfo(
                    registry_key=registry.regk,
                    name=registry.name,
                    issuer_aid=issuer_aid,
                    created_at="",
                    sequence_number=seq_num,
                    no_backers=no_backers,
                )
                registries.append(info)
            return registries

    async def delete_registry(self, registry_key: str) -> bool:
        """Delete a registry from local storage.

        Note: This only removes the registry from local storage. The registry
        and its TEL events still exist in the KERI ecosystem and cannot be
        truly deleted from the global state.

        Args:
            registry_key: The registry prefix (regk) to delete

        Returns:
            True if deleted successfully

        Raises:
            ValueError: If registry not found
        """
        async with self._lock:
            registry = self.regery.regs.get(registry_key)
            if registry is None:
                raise ValueError(f"Registry not found: {registry_key}")

            name = registry.name

            # Remove from Regery's internal structures
            if registry_key in self.regery.regs:
                del self.regery.regs[registry_key]

            log.info(f"Deleted registry from local storage: {name} ({registry_key[:16]}...)")
            return True

    async def get_tel_bytes(self, registry_key: str) -> bytes:
        """Get serialized TEL inception event for witness publishing.

        Uses Reger.cloneTvt() to get properly CESR-encoded TEL event
        with signatures and attachments, suitable for publishing.

        NOTE: TEL events (vcp) cannot be receipted by witnesses directly.
        Use get_anchor_ixn_bytes() to get the anchoring KEL event instead.

        Args:
            registry_key: The registry prefix (regk)

        Returns:
            CESR-encoded TEL inception event with attachments

        Raises:
            ValueError: If registry not found
        """
        async with self._lock:
            registry = self.regery.regs.get(registry_key)
            if registry is None:
                raise ValueError(f"Registry not found: {registry_key}")

            # Use cloneTvt to get properly formatted TEL event with sigs
            # registry.vcp.saidb is the digest of the inception event
            pre = registry_key.encode() if isinstance(registry_key, str) else registry_key
            msg = self.regery.reger.cloneTvt(pre=pre, dig=registry.vcp.saidb)
            return bytes(msg)

    async def get_anchor_ixn_bytes(self, registry_key: str) -> bytes:
        """Get the KEL interaction event that anchors the TEL registry.

        When a registry is created with noBackers=True, the TEL inception
        event (vcp) is anchored to the issuer's KEL via an interaction (ixn)
        event. Witnesses receipt this ixn event, not the vcp directly.

        Args:
            registry_key: The registry prefix (regk)

        Returns:
            CESR-encoded interaction event with signatures

        Raises:
            ValueError: If registry not found or anchor event missing
        """
        async with self._lock:
            registry = self.regery.regs.get(registry_key)
            if registry is None:
                raise ValueError(f"Registry not found: {registry_key}")

            # Get the issuer's hab
            hab = registry.hab
            if hab is None:
                raise ValueError(f"Registry {registry_key} has no associated hab")

            # The anchoring ixn is the latest event on the issuer's KEL
            # after registry creation. Get the latest event.
            identity_mgr = await get_identity_manager()
            hby = identity_mgr.habery

            # Get the latest ixn event for this hab
            # The registry anchor is at the current sequence number
            sn = hab.kever.sn  # Current sequence number
            dgkey = hby.db.getKeLast(hab.pre.encode())
            if dgkey is None:
                raise ValueError(f"No KEL events found for issuer {hab.pre}")

            # Clone the event message with signatures
            msg = hby.db.cloneEvtMsg(pre=hab.pre.encode(), fn=sn, dig=dgkey)
            if msg is None:
                raise ValueError(f"Failed to clone anchor ixn for registry {registry_key}")

            return bytes(msg)


# Module-level singleton
_registry_manager: Optional[CredentialRegistryManager] = None


async def get_registry_manager() -> CredentialRegistryManager:
    """Get or create the registry manager singleton."""
    global _registry_manager
    if _registry_manager is None:
        _registry_manager = CredentialRegistryManager()
        await _registry_manager.initialize()
    return _registry_manager


async def close_registry_manager() -> None:
    """Close the registry manager singleton."""
    global _registry_manager
    if _registry_manager is not None:
        await _registry_manager.close()
        _registry_manager = None


def reset_registry_manager() -> None:
    """Reset the singleton without closing (for testing)."""
    global _registry_manager
    _registry_manager = None
