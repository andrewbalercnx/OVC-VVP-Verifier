"""Schema authorization per organization type.

Sprint 67: Hard-coded mapping from org_type to allowed credential schema SAIDs.
The trust chain structure is defined by the vLEI/VVP specification.

Uses inline SAIDs with comments for clarity — these match
common/vvp/schema/registry.py constants. If a centralized SAID constants
module is created in a future sprint, this mapping should reference it.
"""

from app.db.models import OrgType

# Schema authorization mapping per Sprint 67 spec.
#
# Sprint 67 spec:
#   root_authority  → [QVI Credential]
#   qvi             → [Legal Entity, Legal Entity (Extended)]
#   vetter_authority → [VetterCertification, Governance]
#   regular         → [Brand Credential (Extended), TN Allocation,
#                       TN Allocation (Extended), DE/GCD (delsig)]
#
# Note: A base "Brand Credential" schema does not yet exist as an embedded
# schema (only Extended Brand is available). When a base Brand schema is
# added, its SAID should be included here.
#
# DE/GCD justification: regular AP orgs need DE credentials for dossier
# delegation evidence (delsig). Without this, POST /dossier/create cannot
# include delegation chains. Added per R4 review requirement.

SCHEMA_AUTHORIZATION: dict[OrgType, set[str]] = {
    OrgType.ROOT_AUTHORITY: {
        "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",  # QVI Credential
    },
    OrgType.QVI: {
        "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY",  # Legal Entity
        "EPknTwPpSZi379molapnuN4V5AyhCxz_6TLYdiVNWvbV",  # Extended Legal Entity
    },
    OrgType.VETTER_AUTHORITY: {
        "EOefmhWU2qTpMiEQhXohE6z3xRXkpLloZdhTYIenlD4H",  # VetterCertification
        "EIBowJmxx5hNWQlfXqGcbN0aP_RBuucMW6mle4tAN6TL",  # GSMA Governance
    },
    OrgType.REGULAR: {
        "EK7kPhs5YkPsq9mZgUfPYfU-zq5iSlU8XVYJWqrVPk6g",  # Extended Brand Credential
        "EFvnoHDY7I-kaBBeKlbDbkjG4BaI0nKLGadxBdjMGgSQ",  # TN Allocation
        "EGUh_fVLbjfkYFb5zAsY2Rqq0NqwnD3r5jsdKWLTpU8_",  # Extended TN Allocation
        "EL7irIKYJL9Io0hhKSGWI4OznhwC7qgJG5Qf4aEs6j0o",  # Delegation Establishment (DE/GCD)
    },
}


def is_schema_authorized(org_type: str, schema_said: str) -> bool:
    """Check if an org type is authorized to issue a schema.

    Args:
        org_type: Organization type string value
        schema_said: Schema SAID to check

    Returns:
        True if the org type is authorized to issue the schema
    """
    try:
        ot = OrgType(org_type)
    except ValueError:
        return False
    return schema_said in SCHEMA_AUTHORIZATION.get(ot, set())


def get_authorized_schemas(org_type: str) -> set[str]:
    """Get schema SAIDs authorized for an org type.

    Args:
        org_type: Organization type string value

    Returns:
        Set of authorized schema SAIDs (empty if org_type is invalid)
    """
    try:
        ot = OrgType(org_type)
    except ValueError:
        return set()
    return SCHEMA_AUTHORIZATION.get(ot, set())
