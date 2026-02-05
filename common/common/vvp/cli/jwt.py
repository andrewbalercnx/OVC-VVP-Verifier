"""JWT/PASSporT parsing commands.

Commands:
    vvp jwt parse <token>     Parse JWT structure
    vvp jwt validate <token>  Validate JWT with optional binding
"""

from typing import Any, Optional

import typer

from common.vvp.cli.output import OutputFormat, output, output_error
from common.vvp.cli.utils import (
    EXIT_PARSE_ERROR,
    EXIT_VALIDATION_FAILURE,
    dataclass_to_dict,
    read_input,
)

app = typer.Typer(
    name="jwt",
    help="Parse and validate JWT/PASSporT tokens.",
    no_args_is_help=True,
)


@app.command("parse")
def parse_cmd(
    source: str = typer.Argument(
        ...,
        help="JWT token, file path, or '-' for stdin",
    ),
    format: OutputFormat = typer.Option(
        OutputFormat.json,
        "--format",
        "-f",
        help="Output format",
    ),
    show_raw: bool = typer.Option(
        False,
        "--show-raw",
        help="Include raw base64 parts in output",
    ),
    no_validate: bool = typer.Option(
        False,
        "--no-validate",
        help="Skip validation, parse structure only",
    ),
) -> None:
    """Parse a JWT/PASSporT token and display its structure.

    The token can be provided as:
    - A literal JWT string (header.payload.signature)
    - A file path containing the JWT
    - '-' to read from stdin

    Examples:
        vvp jwt parse "eyJhbGciOiJFZERTQSI..."
        vvp jwt parse token.jwt
        cat token.jwt | vvp jwt parse -
    """
    from common.vvp.cli.adapters import Passport, parse_passport

    # Read input
    jwt_string = read_input(source, binary=False)
    jwt_string = jwt_string.strip()

    # Parse the JWT
    try:
        passport: Passport = parse_passport(jwt_string)
    except Exception as e:
        output_error(
            code="PASSPORT_PARSE_FAILED",
            message=str(e),
            exit_code=EXIT_PARSE_ERROR,
        )
        return  # unreachable, but helps type checker

    # Build output
    result: dict[str, Any] = {
        "header": dataclass_to_dict(passport.header),
        "payload": dataclass_to_dict(passport.payload),
        "signature": {
            "bytes": passport.signature.hex() if passport.signature else None,
            "length": len(passport.signature) if passport.signature else 0,
        },
        "warnings": list(passport.warnings) if passport.warnings else [],
    }

    if show_raw:
        result["raw"] = {
            "header": passport.raw_header,
            "payload": passport.raw_payload,
        }

    output(result, format)


def _extract_dossier_time(
    dossier_path: str,
    errors: list[str],
    warnings: list[str],
) -> Optional[int]:
    """Extract issuance time from a dossier's leaf credential.

    Returns Unix timestamp or None if extraction fails.
    """
    from datetime import datetime

    from common.vvp.cli.adapters import parse_dossier

    try:
        # Read and parse the dossier
        dossier_data = read_input(dossier_path, binary=True)
        if isinstance(dossier_data, str):
            dossier_data = dossier_data.encode("utf-8")

        nodes, _ = parse_dossier(dossier_data)

        if not nodes:
            warnings.append("Dossier is empty, cannot extract time")
            return None

        # Find the leaf credential (one that isn't referenced by others)
        # by looking for the node with no incoming edges
        referenced_saids: set[str] = set()
        for node in nodes:
            # Check edges in the ACDC
            if hasattr(node, "raw") and node.raw:
                import json

                try:
                    acdc = json.loads(node.raw) if isinstance(node.raw, (str, bytes)) else node.raw
                    edges = acdc.get("e", {}) or acdc.get("edges", {})
                    if isinstance(edges, dict):
                        for edge_val in edges.values():
                            if isinstance(edge_val, dict) and "n" in edge_val:
                                referenced_saids.add(edge_val["n"])
                            elif isinstance(edge_val, str) and edge_val.startswith("E"):
                                referenced_saids.add(edge_val)
                except (json.JSONDecodeError, TypeError):
                    pass

        # Find leaf nodes (not referenced by any other)
        leaf_nodes = [n for n in nodes if n.said not in referenced_saids]
        target_node = leaf_nodes[0] if leaf_nodes else nodes[0]

        # Extract datetime from the target node
        if hasattr(target_node, "raw") and target_node.raw:
            import json

            try:
                acdc = json.loads(target_node.raw) if isinstance(target_node.raw, (str, bytes)) else target_node.raw
                dt_str = acdc.get("a", {}).get("dt") or acdc.get("dt")

                if dt_str:
                    # Parse ISO 8601 datetime
                    # Handle formats like: 2024-01-01T12:00:00.000000+00:00
                    dt_str = dt_str.replace("Z", "+00:00")
                    if "." in dt_str:
                        # Has microseconds
                        dt = datetime.fromisoformat(dt_str)
                    else:
                        dt = datetime.fromisoformat(dt_str)

                    unix_ts = int(dt.timestamp())
                    warnings.append(f"Using dossier time: {dt_str} (Unix: {unix_ts})")
                    return unix_ts
            except (json.JSONDecodeError, TypeError, ValueError) as e:
                warnings.append(f"Could not parse dossier datetime: {e}")

        warnings.append("No datetime found in dossier credentials")
        return None

    except Exception as e:
        errors.append(f"Failed to extract time from dossier: {e}")
        return None


@app.command("validate")
def validate_cmd(
    source: str = typer.Argument(
        ...,
        help="JWT token, file path, or '-' for stdin",
    ),
    identity_header: Optional[str] = typer.Option(
        None,
        "--identity",
        "-i",
        help="VVP-Identity header for binding validation",
    ),
    now: Optional[int] = typer.Option(
        None,
        "--now",
        help="Override current time (Unix timestamp) for testing",
    ),
    dossier: Optional[str] = typer.Option(
        None,
        "--dossier",
        "-d",
        help="Dossier file to extract validation time from (uses leaf credential issuance time)",
    ),
    format: OutputFormat = typer.Option(
        OutputFormat.json,
        "--format",
        "-f",
        help="Output format",
    ),
    strict: bool = typer.Option(
        False,
        "--strict",
        help="Fail on any warnings",
    ),
) -> None:
    """Validate a JWT/PASSporT token.

    Performs structural validation and optionally validates binding
    against a VVP-Identity header.

    The --dossier option extracts the issuance time from the dossier's
    leaf credential and uses it for time-based validation. This is useful
    for validating historical JWTs against the time they were issued.

    Examples:
        vvp jwt validate token.jwt
        vvp jwt validate token.jwt --identity "eyJwcHQi..."
        vvp jwt validate token.jwt --dossier dossier.json
        cat token.jwt | vvp jwt validate - --strict
    """
    from common.vvp.cli.adapters import parse_passport, parse_vvp_identity

    # Read input
    jwt_string = read_input(source, binary=False)
    jwt_string = jwt_string.strip()

    errors: list[str] = []
    warnings: list[str] = []

    # Extract time from dossier if provided
    validation_time = now
    if dossier and not now:
        validation_time = _extract_dossier_time(dossier, errors, warnings)

    # Parse the JWT
    try:
        passport = parse_passport(jwt_string)
        warnings.extend(passport.warnings)
    except Exception as e:
        output_error(
            code="PASSPORT_PARSE_FAILED",
            message=str(e),
            exit_code=EXIT_PARSE_ERROR,
        )
        return

    # Parse VVP-Identity if provided
    vvp_identity = None
    if identity_header:
        try:
            vvp_identity = parse_vvp_identity(identity_header)
        except Exception as e:
            errors.append(f"VVP-Identity parse failed: {e}")

    # Validate binding if we have both
    if vvp_identity and passport:
        try:
            from common.vvp.cli.adapters import validate_passport_binding

            validate_passport_binding(passport, vvp_identity, now=validation_time)
        except Exception as e:
            errors.append(f"Binding validation failed: {e}")

    # Determine validity
    is_valid = len(errors) == 0 and (not strict or len(warnings) == 0)

    result: dict[str, Any] = {
        "valid": is_valid,
        "errors": errors,
        "warnings": warnings,
    }

    if validation_time is not None:
        result["validation_time"] = validation_time

    output(result, format)

    if not is_valid:
        raise typer.Exit(EXIT_VALIDATION_FAILURE)


if __name__ == "__main__":
    app()
