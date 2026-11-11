"""op-contract-modify-application-status-check."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-modify-application-status-check"
GROUP = "error-semantics"
SERVICES = ["ec2"]
DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyApplicationStatusCheck updates an existing check's config; DryRun rejects first."""
    from botocore.exceptions import ClientError

    ec2 = ctx.client("ec2")

    try:
        created = ec2.create_application_status_check(
            Protocol="http",
            Port=8080,
            Path="/health",
            FailureThreshold=2,
            SuccessThreshold=2,
            TagSpecifications=[
                {
                    "ResourceType": "application-status-check",
                    "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-appsc-")}],
                }
            ],
        )
    except ClientError as e:
        raise AssertionError(f"CreateApplicationStatusCheck unavailable: {e}")

    check = created["ApplicationStatusCheck"]
    check_id = check["ApplicationStatusCheckId"]
    assert check["Protocol"] == "http"
    assert check["Port"] == 8080
    ctx.on_cleanup(lambda: _delete_check(ec2, check_id))

    # --- error boundary: DryRun must reject before applying the update ---
    code, msg = _error(
        lambda: ec2.modify_application_status_check(
            ApplicationStatusCheckId=check_id, Path="/status", DryRun=True
        )
    )
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert msg == DRY_RUN_MESSAGE, f"expected message {DRY_RUN_MESSAGE!r}, got {msg!r}"

    # DryRun must not have applied the update -- confirm absence via an independent read
    # before the real modification below would otherwise mask a target that mis-applies it.
    unchanged = ec2.describe_application_status_checks(ApplicationStatusCheckIds=[check_id])[
        "ApplicationStatusChecks"
    ][0]
    assert unchanged["Path"] == "/health", f"DryRun must not apply the update, got {unchanged!r}"
    assert unchanged["Port"] == 8080, f"DryRun must not apply the update, got {unchanged!r}"

    # --- success path: modify path/thresholds and observe the update reflected ---
    modified = ec2.modify_application_status_check(
        ApplicationStatusCheckId=check_id,
        Path="/status",
        FailureThreshold=3,
        SuccessThreshold=4,
        Port=8443,
        Protocol="https",
    )["ApplicationStatusCheck"]
    assert modified["ApplicationStatusCheckId"] == check_id
    assert modified["Path"] == "/status"
    assert modified["Protocol"] == "https"
    assert modified["Port"] == 8443
    assert modified["FailureThreshold"] == 3
    assert modified["SuccessThreshold"] == 4

    # independent read: the update must be visible through Describe, not just echoed
    # back by the mutating call's own response.
    persisted = ec2.describe_application_status_checks(ApplicationStatusCheckIds=[check_id])[
        "ApplicationStatusChecks"
    ][0]
    assert persisted["Path"] == "/status", f"expected persisted Path '/status', got {persisted!r}"
    assert persisted["Protocol"] == "https", f"expected persisted Protocol 'https', got {persisted!r}"
    assert persisted["Port"] == 8443, f"expected persisted Port 8443, got {persisted!r}"
    assert persisted["FailureThreshold"] == 3, (
        f"expected persisted FailureThreshold 3, got {persisted!r}"
    )
    assert persisted["SuccessThreshold"] == 4, (
        f"expected persisted SuccessThreshold 4, got {persisted!r}"
    )

    # a nonexistent check id must be rejected distinctly from the DryRun boundary
    notfound_code, notfound_msg = _error(
        lambda: ec2.modify_application_status_check(
            ApplicationStatusCheckId="asc-00000000000000000", Path="/x"
        )
    )
    assert notfound_code == "InvalidApplicationStatusCheckId.NotFound", (
        f"expected InvalidApplicationStatusCheckId.NotFound, got {notfound_code!r}"
    )
    expected = "The application-status-check ID 'asc-00000000000000000' does not exist"
    assert notfound_msg == expected, f"expected message {expected!r}, got {notfound_msg!r}"


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected SUCCESS raises,
    so a target that accepts what AWS refuses fails loudly instead of as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_check(ec2, check_id: str) -> None:
    try:
        ec2.delete_application_status_check(ApplicationStatusCheckId=check_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidApplicationStatusCheckId.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
