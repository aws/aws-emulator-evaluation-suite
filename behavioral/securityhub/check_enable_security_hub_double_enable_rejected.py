"""enable-security-hub-double-enable-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "enable-security-hub-double-enable-rejected"
GROUP = "overly-permissive"
SERVICES = ["securityhub"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:securityhub")
def run(ctx) -> None:
    """A second EnableSecurityHub call on an already-enabled hub is rejected with ResourceConflictException."""
    sh = ctx.client("securityhub")

    # No ctx.on_cleanup: DisableSecurityHub deletes all findings/subscriptions and is not undone
    # by re-enabling, so this check (like its siblings) never disables the hub it adopts/creates.
    # Ensure the hub is enabled first. Its outcome (success vs. already-enabled conflict)
    # depends on account history and is NOT the graded assertion -- it only establishes
    # the deterministic precondition for the check below.
    try:
        sh.enable_security_hub()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceConflictException":
            raise

    hub = sh.describe_hub()
    assert hub.get("HubArn"), f"expected hub to be enabled and describable, got {hub!r}"

    # The one graded, deterministic outcome: with the hub now guaranteed enabled,
    # enabling it again must always be rejected.
    code2, message2 = _error(lambda: sh.enable_security_hub())
    assert code2 == "ResourceConflictException", f"expected ResourceConflictException, got {code2}"
    expected = "Account is already subscribed to Security Hub"
    assert message2 == expected, f"expected message {expected!r}, got {message2!r}"

    # Positive control: the hub is unaffected and still describable/enabled.
    hub2 = sh.describe_hub()
    assert hub2.get("HubArn") == hub["HubArn"], (
        f"hub identity changed after the rejected double-enable: expected {hub['HubArn']!r}, "
        f"got {hub2.get('HubArn')!r}"
    )


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
