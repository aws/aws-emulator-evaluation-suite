"""get-custom-data-identifier-not-found."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "get-custom-data-identifier-not-found"
GROUP = "error-semantics"
SERVICES = ["macie2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:macie")
def run(ctx) -> None:
    """GetCustomDataIdentifier for an id that was never created returns ResourceNotFoundException."""
    _ensure_macie_enabled(ctx)
    macie = ctx.client("macie2")

    # Real AWS validates id shape before existence: a malformed id (e.g. not a UUID) draws
    # ValidationException regardless of whether it was ever created, which is a different
    # contract than "never created". A well-formed-but-unused UUID isolates the not-found path.
    bogus_id = str(uuid.uuid4())
    error = _client_error(lambda: macie.get_custom_data_identifier(id=bogus_id))
    assert error["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a never-created id, got {error['Code']}"
    )
    assert error["Message"] == f"Custom Data Identifier not found for id: {bogus_id}", (
        f"unexpected message: {error['Message']!r}"
    )

    # Positive control in the same file: a real identifier is retrievable.
    cdi_id = macie.create_custom_data_identifier(
        name=ctx.unique_name("sim2real-macie-cdi-"),
        regex=r"[A-Z]{2}\d{6}",
        clientToken=ctx.unique_name("sim2real-macie-cdi-tok-"),
        tags={"sim2real": "true"},
    )["customDataIdentifierId"]
    ctx.on_cleanup(lambda: macie.delete_custom_data_identifier(id=cdi_id))
    fetched = macie.get_custom_data_identifier(id=cdi_id)
    assert fetched["id"] == cdi_id, f"expected GetCustomDataIdentifier to echo id {cdi_id!r}, got {fetched.get('id')!r}"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a lookup real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError for a never-created id, but call SUCCEEDED and returned {result!r}")


def _ensure_macie_enabled(ctx) -> None:
    from botocore.exceptions import ClientError

    macie = ctx.client("macie2")
    try:
        macie.get_macie_session()
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code not in ("ResourceNotFoundException", "AccessDeniedException"):
            raise
        try:
            macie.enable_macie()
        except ClientError as exc2:
            if exc2.response["Error"]["Code"] != "ConflictException":
                raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
