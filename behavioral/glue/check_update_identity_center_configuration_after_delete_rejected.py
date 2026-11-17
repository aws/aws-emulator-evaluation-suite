"""update-identity-center-configuration-after-delete-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-identity-center-configuration-after-delete-rejected"
GROUP = "negative-classes"
SERVICES = ["glue", "sso-admin"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """UpdateGlueIdentityCenterConfiguration on a deleted configuration raises
    EntityNotFoundException, and the configuration is re-creatable afterward.
    """
    glue = ctx.client("glue")
    instance_arn = _own_identity_center_instance(ctx)

    _clear_existing_configuration(glue)
    first_config = _create_configuration_with_retry(glue, instance_arn, False)
    ctx.on_cleanup(lambda: _delete_configuration_idempotent(glue, first_config["ApplicationArn"]))

    # Positive control: Update succeeds while the configuration is alive.
    glue.update_glue_identity_center_configuration(UserBackgroundSessionsEnabled=True)
    live = glue.get_glue_identity_center_configuration()
    assert live["UserBackgroundSessionsEnabled"] is True, (
        f"expected the live-configuration update to take effect, got {live!r}"
    )

    glue.delete_glue_identity_center_configuration()

    code, message = _error(lambda: glue.update_glue_identity_center_configuration(UserBackgroundSessionsEnabled=False))
    assert code == "EntityNotFoundException", (
        f"expected UpdateGlueIdentityCenterConfiguration on a deleted configuration to raise "
        f"EntityNotFoundException, got {code!r}"
    )
    expected_message = "Idc application not found. Need to create glue application first."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    get_code, _ = _error(lambda: glue.get_glue_identity_center_configuration())
    assert get_code == "EntityNotFoundException", (
        f"expected the rejected update to leave no configuration behind, got {get_code!r}"
    )

    recreated = glue.create_glue_identity_center_configuration(
        InstanceArn=instance_arn, UserBackgroundSessionsEnabled=False
    )
    ctx.on_cleanup(lambda: _delete_configuration_idempotent(glue, recreated["ApplicationArn"]))
    assert recreated.get("ApplicationArn"), (
        f"expected the configuration slot to be reusable after the rejected update, got {recreated!r}"
    )


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
