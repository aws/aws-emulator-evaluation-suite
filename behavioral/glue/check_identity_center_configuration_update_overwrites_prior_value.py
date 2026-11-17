"""identity-center-configuration-update-overwrites-prior-value."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "identity-center-configuration-update-overwrites-prior-value"
GROUP = "state-machine"
SERVICES = ["glue", "sso-admin"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """UpdateGlueIdentityCenterConfiguration replaces UserBackgroundSessionsEnabled in place:
    each update is visible on the next Get and the prior value is gone, not merged.
    """
    glue = ctx.client("glue")
    instance_arn = _own_identity_center_instance(ctx)

    _clear_existing_configuration(glue)
    created_config = _create_configuration_with_retry(glue, instance_arn, True)
    ctx.on_cleanup(lambda: _delete_configuration_idempotent(glue, created_config["ApplicationArn"]))

    created = glue.get_glue_identity_center_configuration()
    assert created["UserBackgroundSessionsEnabled"] is True, (
        f"expected UserBackgroundSessionsEnabled=True right after create, got {created!r}"
    )

    glue.update_glue_identity_center_configuration(UserBackgroundSessionsEnabled=False)
    flipped = glue.get_glue_identity_center_configuration()
    assert flipped["UserBackgroundSessionsEnabled"] is False, (
        f"expected UpdateGlueIdentityCenterConfiguration(False) to overwrite the prior True, "
        f"got {flipped!r}"
    )
    assert flipped["InstanceArn"] == instance_arn, (
        f"expected InstanceArn to stay {instance_arn}, got {flipped.get('InstanceArn')}"
    )

    glue.update_glue_identity_center_configuration(UserBackgroundSessionsEnabled=True)
    restored = glue.get_glue_identity_center_configuration()
    assert restored["UserBackgroundSessionsEnabled"] is True, (
        f"expected a second update back to True to overwrite the False, got {restored!r}"
    )

    glue.delete_glue_identity_center_configuration()
    code, message = _error(lambda: glue.get_glue_identity_center_configuration())
    assert code == "EntityNotFoundException", (
        f"expected GetGlueIdentityCenterConfiguration to fail after delete, got {code!r}"
    )
    expected_message = "Idc application not found. Need to create glue application first."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn) -> tuple[str, str]:
    """Call fn(); return the (Code, Message) of the ClientError it raises. An unexpected
    success raises, so an emulator accepting what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _clear_existing_configuration(glue) -> None:
    """Glue allows exactly one identity center configuration per account; remove any
    leftover from an earlier run before creating this check's own.
    """
    try:
        existing = glue.get_glue_identity_center_configuration()
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "EntityNotFoundException":
            return
        raise
    _delete_configuration_idempotent(glue, existing["ApplicationArn"])


def _delete_configuration_idempotent(glue, application_arn: str) -> None:
    try:
        live = glue.get_glue_identity_center_configuration()
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "EntityNotFoundException":
            return
        raise
    assert live["ApplicationArn"] == application_arn, (
        f"refusing to delete a configuration ({live['ApplicationArn']!r}) this check did not create "
        f"(expected {application_arn!r})"
    )
    glue.delete_glue_identity_center_configuration()


def _create_configuration_with_retry(glue, instance_arn: str, background_sessions_enabled: bool) -> dict:
    """A just-created Identity Center instance is not immediately usable as a Glue
    application host, so the first create after provisioning one is retried on
    InvalidInputException for a bounded window.
    """
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return glue.create_glue_identity_center_configuration(
                InstanceArn=instance_arn, UserBackgroundSessionsEnabled=background_sessions_enabled
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidInputException" and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise


def _own_identity_center_instance(ctx) -> str:
    """The account's IAM Identity Center instance ARN, provisioning (and tearing down) a
    standalone one if the account has none.
    """
    sso = ctx.client("sso-admin")
    instances = sso.list_instances().get("Instances", [])
    if instances:
        return instances[0]["InstanceArn"]

    instance_arn = _create_instance_with_retry(sso, ctx.unique_name("sim2real-glue-idc-"))
    ctx.on_cleanup(lambda: sso.delete_instance(InstanceArn=instance_arn))
    return instance_arn


def _create_instance_with_retry(sso, name: str) -> str:
    """A standalone instance this account recently deleted leaves its service-linked role
    mid-deletion for a while, during which a new CreateInstance is refused; retry it out.
    """
    deadline = time.monotonic() + 180.0
    while True:
        try:
            return sso.create_instance(Name=name)["InstanceArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ConflictException" and time.monotonic() < deadline:
                time.sleep(2.0)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
