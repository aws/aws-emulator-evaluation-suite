"""get-migration-malformed-id-error-semantics."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-migration-malformed-id-error-semantics"
GROUP = "error-semantics"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetMigration fails with ValidationException "Invalid migrationId format: abc" for a malformed id and
    with ResourceNotFoundException and its exact message for an unknown UUID id, two distinct codes.
    """
    opensearch = ctx.client("opensearch")

    # Positive control: the client and credentials are otherwise fully functional against an
    # always-available, ungated control-plane read, so the rejections below reflect the
    # migrationId classification itself, not a broken connection or credential set up.
    opensearch.list_domain_names()

    malformed_id = "abc"  # not UUID-shaped; migration ids are generated as UUIDs
    malformed_code, malformed_message = _error(lambda: opensearch.get_migration(migrationId=malformed_id))
    assert malformed_code == "ValidationException", (
        f"expected ValidationException for a syntactically invalid migration id, "
        f"got {malformed_code}"
    )
    expected = f"Invalid migrationId format: {malformed_id}"
    assert malformed_message == expected, f"expected message {expected!r}, got {malformed_message!r}"

    missing_id = str(uuid.uuid4())
    missing_code, missing_message = _error(lambda: opensearch.get_migration(migrationId=missing_id))
    assert missing_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a well-formed but nonexistent migration id, "
        f"got {missing_code}"
    )
    # The service reads the id's leading segment as the owning application id.
    expected = f"Application {missing_id.split('-')[0]} not found"
    assert missing_message == expected, f"expected message {expected!r}, got {missing_message!r}"

    assert malformed_code != missing_code, (
        f"malformed-input and resource-not-found rejections must not collapse into the same "
        f"error code, got {malformed_code!r} for both"
    )


def _error(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
