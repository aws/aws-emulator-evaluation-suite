"""identity-center-configuration-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "identity-center-configuration-lifecycle"
GROUP = "state-machine"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """CreateGlueIdentityCenterConfiguration establishes the configuration,
    GetGlueIdentityCenterConfiguration returns it, and DeleteGlueIdentityCenterConfiguration
    removes it so a subsequent Get raises EntityNotFoundException."""

    instance_arn = _identity_center_instance_arn(ctx)

    glue = ctx.client("glue")
    glue.create_glue_identity_center_configuration(InstanceArn=instance_arn)

    ctx.on_cleanup(lambda: _ignore_missing(glue.delete_glue_identity_center_configuration))

    got = glue.get_glue_identity_center_configuration()
    assert got["InstanceArn"] == instance_arn, (
        f"expected GetGlueIdentityCenterConfiguration to reflect InstanceArn={instance_arn}, got {got.get('InstanceArn')}"
    )
    assert got.get("ApplicationArn"), (
        f"expected GetGlueIdentityCenterConfiguration to return a non-empty ApplicationArn, got {got!r}"
    )

    glue.delete_glue_identity_center_configuration()

    code, message = _error(lambda: glue.get_glue_identity_center_configuration())
    assert code == "EntityNotFoundException", (
        f"expected GetGlueIdentityCenterConfiguration to fail with EntityNotFoundException after delete, got {code!r}"
    )
    expected = "Idc application not found. Need to create glue application first."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


# ===== helpers =====
def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. An unexpected
    success raises, so an emulator accepting what AWS refuses fails loudly."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _ignore_missing(fn):
    """Run a teardown call; a resource that is already gone is not a leak."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _identity_center_instance_arn(ctx) -> str:
    """The account's IAM Identity Center instance ARN, creating one if none exists.

    `sso-admin:CreateInstance` provisions a STANDALONE (non-Organizations) instance, so the
    prerequisite is satisfiable in-check and an account without an instance does not block the
    check.
    """
    import time

    sso = ctx.client("sso-admin")
    instances = sso.list_instances().get("Instances", [])
    if instances:
        instance_arn = instances[0]["InstanceArn"]
    else:
        # Exactly one instance is allowed per account, and deleting it would disrupt any other
        # check relying on it, so one created here is deliberately never torn down.
        instance_arn = sso.create_instance()["InstanceArn"]
    deadline = time.time() + 120
    status = None
    while time.time() < deadline:
        status = sso.describe_instance(InstanceArn=instance_arn)["Status"]
        if status == "ACTIVE":
            return instance_arn
        if status in ("CREATE_FAILED", "DELETE_IN_PROGRESS"):
            raise RuntimeError(f"IAM Identity Center instance in unexpected state: {status}")
        time.sleep(3)
    raise RuntimeError(
        f"IAM Identity Center instance did not become ACTIVE in time (last status: {status})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
