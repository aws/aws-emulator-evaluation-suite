"""delete-identity-center-configuration-concurrent-delete-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-identity-center-configuration-concurrent-delete-rejected"
GROUP = "concurrency"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """Deleting the account's Glue Identity Center configuration twice in a row: the first delete
    succeeds and the second is refused with EntityNotFoundException and its exact message, the
    configuration then reads as not found, and recreating it succeeds."""
    ssoadmin = ctx.client("sso-admin")
    instances = ssoadmin.list_instances().get("Instances", [])
    if instances:
        instance_arn = instances[0]["InstanceArn"]
    else:
        # CreateInstance self-provisions a siloed IAM Identity Center instance for a
        # standalone/member account; only the organization *management* account is rejected.
        instance_arn = ssoadmin.create_instance(
            Name=ctx.unique_name("glue-idc-"),
            Tags=[{"Key": "simparity-check", "Value": CHECK}],
        )["InstanceArn"]
        ctx.on_cleanup(lambda: _ignore_missing(lambda: ssoadmin.delete_instance(InstanceArn=instance_arn)))
        # A freshly created instance is CREATE_IN_PROGRESS before it can back a managed
        # application; Glue's CreateGlueIdentityCenterConfiguration rejects it until ACTIVE.
        _wait_instance_active(ssoadmin, instance_arn, deadline_s=_wait_s(ctx, 120))

    glue = ctx.client("glue")
    # Reset to a known state (in case a prior run/other test left a configuration behind).
    _ignore_missing(lambda: glue.delete_glue_identity_center_configuration())

    glue.create_glue_identity_center_configuration(InstanceArn=instance_arn)
    ctx.on_cleanup(lambda: _ignore_missing(glue.delete_glue_identity_center_configuration))

    glue.delete_glue_identity_center_configuration()
    second = _refusal(lambda: glue.delete_glue_identity_center_configuration())
    assert second == ("EntityNotFoundException", _NOT_FOUND), (
        f"expected the repeated delete to be refused as not found, got {second}"
    )

    # Effect: the configuration is truly gone (not half-deleted / still present).
    gone = _refusal(lambda: glue.get_glue_identity_center_configuration())
    assert gone == ("EntityNotFoundException", _NOT_FOUND), gone

    # Positive control (same file): recreating it afterward succeeds normally.
    glue.create_glue_identity_center_configuration(InstanceArn=instance_arn)
    recreated = glue.get_glue_identity_center_configuration()
    assert recreated["InstanceArn"] == instance_arn


# ===== helpers =====
_NOT_FOUND = "Idc application not found. Need to create glue application first."


def _wait_s(ctx, cap_s):
    """cap_s, shortened so the wait ends before the runner's budget does."""
    left = ctx.time_left()
    if left is None:
        return cap_s
    return max(1.0, min(cap_s, left - 10.0))


def _wait_instance_active(ssoadmin, instance_arn, deadline_s: float = 120.0, interval_s: float = 3.0) -> None:
    start = time.monotonic()
    while True:
        status = ssoadmin.describe_instance(InstanceArn=instance_arn)["Status"]
        if status == "ACTIVE":
            return
        if status == "CREATE_FAILED":
            raise AssertionError(f"IAM Identity Center instance {instance_arn} entered CREATE_FAILED")
        if time.monotonic() - start >= deadline_s:
            raise AssertionError(
                f"IAM Identity Center instance {instance_arn} did not reach ACTIVE within "
                f"{deadline_s}s (last status: {status})"
            )
        time.sleep(interval_s)


def _refusal(fn):
    """Return the (code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _ignore_missing(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("EntityNotFoundException", "ResourceNotFoundException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
