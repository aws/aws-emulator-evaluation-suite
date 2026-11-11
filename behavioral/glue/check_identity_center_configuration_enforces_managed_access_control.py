"""identity-center-configuration-enforces-managed-access-control."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "identity-center-configuration-enforces-managed-access-control"
GROUP = "server-side"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """With no prior configuration (GetGlueIdentityCenterConfiguration is EntityNotFound),
    CreateGlueIdentityCenterConfiguration is reflected by Get with the same InstanceArn and the
    ApplicationArn that Create returned."""

    instance_arn = _get_instance_arn(ctx)

    glue = ctx.client("glue")
    # A configuration this check did not create must not be overwritten or deleted, so the
    # account must start without one; an existing one makes this call succeed and fail the run.
    code, message = _error(lambda: glue.get_glue_identity_center_configuration())
    assert code == "EntityNotFoundException", (
        f"expected no Glue Identity Center configuration before the check, got {code!r}"
    )
    expected = "Idc application not found. Need to create glue application first."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    created = glue.create_glue_identity_center_configuration(InstanceArn=instance_arn)
    ctx.on_cleanup(lambda: glue.delete_glue_identity_center_configuration())

    fetched = glue.get_glue_identity_center_configuration()
    assert fetched["InstanceArn"] == instance_arn, (
        f"expected InstanceArn {instance_arn!r} on the fetched configuration, got "
        f"{fetched.get('InstanceArn')!r}"
    )
    assert fetched["ApplicationArn"] == created["ApplicationArn"], (
        f"GetGlueIdentityCenterConfiguration returned ApplicationArn "
        f"{fetched.get('ApplicationArn')!r}, which diverges from the "
        f"{created.get('ApplicationArn')!r} CreateGlueIdentityCenterConfiguration itself reported"
    )
    assert fetched["ApplicationArn"].startswith("arn:"), (
        f"ApplicationArn {fetched['ApplicationArn']!r} is not a real ARN"
    )


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. An unexpected
    success raises, so an emulator accepting what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _get_instance_arn(ctx):
    import time

    sso = ctx.client("sso-admin")
    instances = sso.list_instances().get("Instances", [])
    if instances:
        instance_arn = instances[0]["InstanceArn"]
    else:
        # Exactly one IAM Identity Center instance is allowed per account, and deleting it
        # would disrupt any other check relying on it, so if we must create one here we
        # deliberately never tear it down.
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
    raise RuntimeError(f"IAM Identity Center instance did not become ACTIVE in time (last status: {status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
