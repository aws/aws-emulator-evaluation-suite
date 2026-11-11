"""get-migration-unknown-id-error-code."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-migration-unknown-id-error-code"
GROUP = "error-semantics"
SERVICES = ["opensearch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetMigration for an unknown migrationId fails with ResourceNotFoundException and its exact message,
    while ListDomainNames on the same client answers with a DomainNames list.
    """
    client = ctx.client("opensearch")

    # Positive control: the client and credentials are otherwise fully functional against
    # an always-available, ungated control-plane read. Without this, the ResourceNotFoundException
    # asserted below is indistinguishable from a broken connection or credential set-up that
    # happens to raise the same-looking error for every call.
    control = client.list_domain_names()
    assert "DomainNames" in control, f"expected a DomainNames list from a healthy client, got {control!r}"

    fake_migration_id = ctx.unique_name("sim2real-migration-")

    code, message = _error(lambda: client.get_migration(migrationId=fake_migration_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    # The service reads the id's leading segment as the owning application id.
    expected = f"Application {fake_migration_id.split('-')[0]} not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


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
