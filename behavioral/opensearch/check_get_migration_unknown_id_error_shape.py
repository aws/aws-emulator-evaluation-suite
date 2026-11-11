"""get-migration-unknown-id-error-shape."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-migration-unknown-id-error-shape"
GROUP = "error-semantics"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetMigration for two different unknown migrationIds each fails with ResourceNotFoundException and its
    exact message, never DisabledOperationException.
    """
    client = ctx.client("opensearch")

    # Sanity/positive control: the client and credentials are otherwise fully functional
    # against an always-available, ungated control-plane read. This proves the
    # ResourceNotFoundException below reflects the migrationId lookup specifically, not a
    # broken connection or credential set up.
    client.list_domain_names()

    first_id = ctx.unique_name("sim2real-mig-")
    second_id = ctx.unique_name("sim2real-mig-")

    code_1, message_1 = _error(lambda: client.get_migration(migrationId=first_id))
    code_2, message_2 = _error(lambda: client.get_migration(migrationId=second_id))

    assert code_1 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code_1}"
    assert code_2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code_2}"
    # The service reads each id's leading segment as the owning application id.
    expected_1 = f"Application {first_id.split('-')[0]} not found"
    expected_2 = f"Application {second_id.split('-')[0]} not found"
    assert message_1 == expected_1, f"expected message {expected_1!r}, got {message_1!r}"
    assert message_2 == expected_2, f"expected message {expected_2!r}, got {message_2!r}"
    # Never a blanket feature-gate rejection, even though DisabledOperationException is also
    # declared for this operation -- the two distinct synthetic ids both fail the same way,
    # which is what a per-id existence check (not a feature gate) produces.
    assert code_1 != "DisabledOperationException", (
        f"expected a per-id ResourceNotFoundException, got a blanket DisabledOperationException "
        f"for first_id={first_id!r}"
    )
    assert code_2 != "DisabledOperationException", (
        f"expected a per-id ResourceNotFoundException, got a blanket DisabledOperationException "
        f"for second_id={second_id!r}"
    )


def _error(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a nonexistent migrationId is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected GetMigration to reject an unknown id, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
