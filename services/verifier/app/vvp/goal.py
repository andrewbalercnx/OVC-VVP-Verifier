"""Business logic verification per spec §5A Step 13.

This module validates PASSporT `goal` claims against verifier policy
and delegated signer constraints. Per §5.1.1-2.13:
- If goal present, confirm verifier accepts this goal (per local policy)
- Check delegated signer credential constraints (hours, geographies)
- Verify call attributes match credential limitations

Geographic constraints result in INDETERMINATE when GeoIP is unavailable
(per Reviewer guidance - can't verify without GeoIP lookup).
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

from .api_models import ClaimStatus, ErrorCode

log = logging.getLogger(__name__)


@dataclass
class ClaimBuilder:
    """Accumulates evidence and failures for a single claim."""

    name: str
    status: ClaimStatus = ClaimStatus.VALID
    reasons: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)

    def fail(self, status: ClaimStatus, reason: str) -> None:
        """Record a failure. INVALID always wins over INDETERMINATE."""
        if status == ClaimStatus.INVALID:
            self.status = ClaimStatus.INVALID
        elif status == ClaimStatus.INDETERMINATE and self.status == ClaimStatus.VALID:
            self.status = ClaimStatus.INDETERMINATE
        self.reasons.append(reason)

    def add_evidence(self, ev: str) -> None:
        """Add evidence string."""
        self.evidence.append(ev)


@dataclass
class GoalPolicyConfig:
    """Configuration for goal acceptance policy.

    Attributes:
        accepted_goals: Set of goals accepted by this verifier.
            Empty set means accept all goals.
        reject_unknown: If True, reject goals not in accepted_goals.
            If False, accept unknown goals with a warning.
        geo_enforced: If True, geographic constraints trigger INDETERMINATE
            when GeoIP is unavailable. If False, skip geo checks (policy deviation).
    """

    accepted_goals: FrozenSet[str] = field(default_factory=frozenset)
    reject_unknown: bool = False
    geo_enforced: bool = True


@dataclass
class SignerConstraints:
    """Constraints on delegated signer extracted from DE credential.

    Attributes:
        hours_of_operation: Tuple of (start_hour, end_hour) in UTC.
            Calls outside this range are rejected.
        geographies: List of ISO 3166-1 alpha-2 country codes.
            Callers outside these geographies are rejected.
    """

    hours_of_operation: Optional[Tuple[int, int]] = None
    geographies: Optional[List[str]] = None


def verify_goal_policy(
    goal: str, accepted_goals: FrozenSet[str], reject_unknown: bool
) -> Tuple[bool, str]:
    """Check if verifier accepts this goal per local policy.

    Per §5.1.1-2.13: Confirm verifier accepts this goal.

    Args:
        goal: Goal string from PASSporT
        accepted_goals: Set of accepted goals (empty = accept all)
        reject_unknown: Whether to reject unknown goals

    Returns:
        Tuple of (is_accepted, evidence_or_reason)
    """
    if not accepted_goals:
        # Empty policy = accept all goals
        return True, f"goal_accepted:{goal}(policy:accept_all)"

    if goal in accepted_goals:
        return True, f"goal_accepted:{goal}(in_whitelist)"

    if reject_unknown:
        return False, f"Goal '{goal}' rejected by policy (not in whitelist)"

    # Accept unknown with warning
    log.warning(f"Goal '{goal}' not in whitelist, accepting (reject_unknown=False)")
    return True, f"goal_accepted:{goal}(unknown_allowed)"


def extract_signer_constraints(de_credential: Optional[Any]) -> SignerConstraints:
    """Extract delegated signer constraints from DE credential.

    Per §5.1.1-2.13: Check delegated signer credential constraints.

    Args:
        de_credential: Delegation edge credential (may be None)

    Returns:
        SignerConstraints extracted from credential
    """
    if de_credential is None:
        return SignerConstraints()

    # Get attributes from DE credential
    attrs = getattr(de_credential, "attributes", None)
    if attrs is None:
        raw = getattr(de_credential, "raw", {})
        attrs = raw.get("a", {})

    if not isinstance(attrs, dict):
        return SignerConstraints()

    hours = None
    geographies = None

    # Look for hours constraint
    # Common field names: hours, operatingHours, hours_of_operation, schedule
    for field_name in ["hours", "operatingHours", "hours_of_operation", "schedule"]:
        if field_name in attrs:
            hours_value = attrs[field_name]
            # Parse hours format: "09-17", [9, 17], {"start": 9, "end": 17}
            if isinstance(hours_value, str) and "-" in hours_value:
                try:
                    parts = hours_value.split("-")
                    hours = (int(parts[0]), int(parts[1]))
                except (ValueError, IndexError):
                    pass
            elif isinstance(hours_value, (list, tuple)) and len(hours_value) == 2:
                try:
                    hours = (int(hours_value[0]), int(hours_value[1]))
                except (ValueError, TypeError):
                    pass
            elif isinstance(hours_value, dict):
                try:
                    hours = (
                        int(hours_value.get("start", 0)),
                        int(hours_value.get("end", 24)),
                    )
                except (ValueError, TypeError):
                    pass
            break

    # Look for geography constraint
    # Common field names: geo, geographies, countries, regions
    for field_name in ["geo", "geographies", "countries", "regions"]:
        if field_name in attrs:
            geo_value = attrs[field_name]
            if isinstance(geo_value, list):
                geographies = [str(g).upper() for g in geo_value]
            elif isinstance(geo_value, str):
                # Comma-separated list
                geographies = [g.strip().upper() for g in geo_value.split(",")]
            break

    return SignerConstraints(hours_of_operation=hours, geographies=geographies)


def verify_signer_constraints(
    constraints: SignerConstraints,
    call_time: datetime,
    caller_geo: Optional[str] = None,
    geo_enforced: bool = True,
) -> Tuple[ClaimStatus, List[str]]:
    """Verify call attributes match credential constraints.

    Per §5.1.1-2.13: Verify call attributes match credential limitations.

    Args:
        constraints: Signer constraints from DE credential
        call_time: Time of the call (UTC)
        caller_geo: Caller geography (ISO 3166-1 alpha-2), or None if unknown
        geo_enforced: If True, missing geo triggers INDETERMINATE

    Returns:
        Tuple of (status, list of evidence/reasons)
    """
    evidence = []
    status = ClaimStatus.VALID

    # Check hours of operation
    if constraints.hours_of_operation is not None:
        start_hour, end_hour = constraints.hours_of_operation
        call_hour = call_time.hour

        # Handle overnight ranges (e.g., 22-06)
        if start_hour <= end_hour:
            # Normal range (e.g., 09-17)
            in_range = start_hour <= call_hour < end_hour
        else:
            # Overnight range (e.g., 22-06)
            in_range = call_hour >= start_hour or call_hour < end_hour

        if in_range:
            evidence.append(f"hours_valid:{call_hour}h_in_{start_hour}-{end_hour}")
        else:
            return (
                ClaimStatus.INVALID,
                [f"Call at {call_hour}:00 UTC outside permitted hours {start_hour}-{end_hour}"],
            )

    # Check geography constraints
    if constraints.geographies is not None:
        if caller_geo is None:
            if geo_enforced:
                # Can't verify geo without GeoIP lookup
                return (
                    ClaimStatus.INDETERMINATE,
                    ["Geographic constraints present but caller geography unknown (GeoIP unavailable)"],
                )
            else:
                # Policy deviation: skip geo check
                log.warning(
                    "Geo constraints present but GeoIP unavailable, skipping (geo_enforced=False)"
                )
                evidence.append("geo_skipped:geoip_unavailable")
        else:
            caller_geo_upper = caller_geo.upper()
            if caller_geo_upper in constraints.geographies:
                evidence.append(f"geo_valid:{caller_geo_upper}")
            else:
                return (
                    ClaimStatus.INVALID,
                    [f"Caller in {caller_geo_upper}, not in permitted geographies {constraints.geographies}"],
                )

    if not evidence:
        evidence.append("no_constraints")

    return status, evidence


def is_goal_subset(potential_subset: str, potential_superset: str) -> bool:
    """Check if one goal is a subset of another.

    Goals are hierarchical codes separated by '.' (e.g., "billing.payment.confirm").
    A goal is a subset if it's a more specific version of the superset.

    Examples:
    - "billing.payment" is subset of "billing"
    - "billing.payment.confirm" is subset of "billing.payment"
    - "billing" is superset of "billing.payment"

    Args:
        potential_subset: The more specific goal
        potential_superset: The more general goal

    Returns:
        True if potential_subset is a subset (equal or more specific) of potential_superset
    """
    # Equal goals are considered subsets of each other
    if potential_subset == potential_superset:
        return True

    # Check if subset starts with superset followed by '.'
    # e.g., "billing.payment" starts with "billing."
    return potential_subset.startswith(potential_superset + ".")


def validate_goal_overlap(
    callee_goal: Optional[str],
    caller_goal: Optional[str],
) -> Tuple[ClaimStatus, List[str]]:
    """Validate caller and callee goals overlap appropriately.

    Per VVP §5.2 (draft-04):
    - "if the passport includes a non-null value for the optional goal claim,
       and the preceding INVITE included a VVP passport that also declared a goal,
       confirm that the callee's and caller's goals overlap
       (one must be a subset of the other)"

    Subset rules (hierarchical goals like "billing.payment.confirm"):
    - If callee_goal is subset of caller_goal → VALID
    - If caller_goal is subset of callee_goal → VALID
    - If neither is subset → INVALID
    - If either is None → VALID (no overlap required)

    Args:
        callee_goal: Goal from callee's PASSporT (may be None)
        caller_goal: Goal from caller's PASSporT (may be None)

    Returns:
        Tuple of (ClaimStatus, list of evidence/reasons)
    """
    # If either goal is missing, overlap check is not required
    if callee_goal is None:
        return ClaimStatus.VALID, ["goal_overlap:callee_goal_absent(not_required)"]

    if caller_goal is None:
        return ClaimStatus.VALID, ["goal_overlap:caller_goal_absent(not_required)"]

    # Both goals present - check for subset relationship
    if is_goal_subset(callee_goal, caller_goal):
        # Callee goal is equal to or more specific than caller goal
        return ClaimStatus.VALID, [f"goal_overlap:callee({callee_goal})_subset_of_caller({caller_goal})"]

    if is_goal_subset(caller_goal, callee_goal):
        # Caller goal is more specific than callee goal (callee is superset)
        return ClaimStatus.VALID, [f"goal_overlap:caller({caller_goal})_subset_of_callee({callee_goal})"]

    # Goals don't overlap - neither is subset of the other
    return ClaimStatus.INVALID, [
        f"Goal mismatch: callee '{callee_goal}' and caller '{caller_goal}' do not overlap"
    ]


def verify_goal_overlap(
    callee_passport,  # Passport type
    caller_passport,  # Optional Passport type
) -> Optional[ClaimBuilder]:
    """Verify goal overlap between callee and caller PASSporTs.

    Per §5B Step 14: If both passports have goals, verify they overlap.
    This claim is REQUIRED when both goals are present, omitted otherwise.

    Args:
        callee_passport: Parsed callee PASSporT
        caller_passport: Parsed caller PASSporT (may be None)

    Returns:
        ClaimBuilder for goal_overlap_verified claim, or None if not applicable
    """
    callee_goal = getattr(callee_passport.payload, "goal", None) if callee_passport else None
    caller_goal = getattr(caller_passport.payload, "goal", None) if caller_passport else None

    # If either goal is absent, overlap check is not required (omit claim)
    if callee_goal is None or caller_goal is None:
        return None

    # Both goals present - this claim is REQUIRED
    claim = ClaimBuilder("goal_overlap_verified")
    claim.add_evidence(f"callee_goal:{callee_goal}")
    claim.add_evidence(f"caller_goal:{caller_goal}")

    status, results = validate_goal_overlap(callee_goal, caller_goal)

    if status == ClaimStatus.VALID:
        for ev in results:
            claim.add_evidence(ev)
    else:
        for reason in results:
            claim.fail(ClaimStatus.INVALID, reason)

    return claim


def verify_business_logic(
    passport,  # Passport type
    dossier_acdcs: Dict[str, Any],
    de_credential: Optional[Any],
    policy: GoalPolicyConfig,
    call_time: Optional[datetime] = None,
    caller_geo: Optional[str] = None,
) -> Optional[ClaimBuilder]:
    """Verify business logic claims if goal present in PASSporT.

    Per §5A Step 13: If passport includes non-null goal claim,
    confirm verifier accepts this goal and check signer constraints.

    Args:
        passport: Parsed PASSporT object
        dossier_acdcs: Dict mapping SAID to ACDC objects
        de_credential: Delegation edge credential (if delegation present)
        policy: Goal policy configuration
        call_time: Time of the call (defaults to now)
        caller_geo: Caller geography for geo constraint checking

    Returns:
        ClaimBuilder for business_logic_verified claim, or None if no goal
    """
    # Check if goal is present
    goal = getattr(passport.payload, "goal", None)
    if goal is None:
        return None  # No goal, no verification needed

    claim = ClaimBuilder("business_logic_verified")
    claim.add_evidence(f"goal:{goal}")

    # Use current time if not provided
    if call_time is None:
        call_time = datetime.now(timezone.utc)

    # Verify goal against policy
    goal_accepted, goal_evidence = verify_goal_policy(
        goal, policy.accepted_goals, policy.reject_unknown
    )
    if goal_accepted:
        claim.add_evidence(goal_evidence)
    else:
        claim.fail(ClaimStatus.INVALID, goal_evidence)
        return claim

    # Extract and verify signer constraints
    constraints = extract_signer_constraints(de_credential)

    if constraints.hours_of_operation or constraints.geographies:
        claim.add_evidence(
            f"constraints:hours={constraints.hours_of_operation},geo={constraints.geographies}"
        )

    status, constraint_results = verify_signer_constraints(
        constraints, call_time, caller_geo, policy.geo_enforced
    )

    if status == ClaimStatus.VALID:
        for ev in constraint_results:
            claim.add_evidence(ev)
    elif status == ClaimStatus.INDETERMINATE:
        for reason in constraint_results:
            claim.fail(ClaimStatus.INDETERMINATE, reason)
    else:
        for reason in constraint_results:
            claim.fail(ClaimStatus.INVALID, reason)

    return claim
