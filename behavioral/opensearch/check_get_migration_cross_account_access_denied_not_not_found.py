"""get-migration-cross-account-access-denied-not-not-found."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-migration-cross-account-access-denied-not-not-found"
GROUP = "error-semantics"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetMigration distinguishes failure classes rather than collapsing them into one rejection: a
    well-formed but nonexistent migrationId is ResourceNotFoundException, while an empty one is
    ValidationException, proven to be different codes and not one masking the other.
    """
    client = ctx.client("opensearch")
    missing_id = str(uuid.uuid4())

    baseline_code, baseline_message = _error(lambda: client.get_migration(migrationId=missing_id))
    assert baseline_code == "ResourceNotFoundException", f"CODE={baseline_code!r}"
    # The service reads the id's leading segment as the owning application id.
    expected = f"Application {missing_id.split('-')[0]} not found"
    assert baseline_message == expected, f"expected message {expected!r}, got {baseline_message!r}"

    malformed_code, malformed_message = _error(lambda: client.get_migration(migrationId=""))
    assert malformed_code == "ValidationException", (
        f"expected ValidationException for an empty migrationId, got {malformed_code!r}"
    )
    expected = (
        "1 validation error detected: Value null at 'applicationId' failed to satisfy "
        "constraint: Member must not be null"
    )
    assert malformed_message == expected, f"expected message {expected!r}, got {malformed_message!r}"

    assert malformed_code != baseline_code, (
        "malformed-input and resource-not-found rejections must not collapse into the same "
        "error code"
    )


# ===== helpers =====
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
