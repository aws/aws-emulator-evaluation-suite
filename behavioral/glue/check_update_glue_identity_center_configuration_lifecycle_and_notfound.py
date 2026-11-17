"""update-glue-identity-center-configuration-lifecycle-and-notfound."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-glue-identity-center-configuration-lifecycle-and-notfound"
GROUP = "state-machine"
SERVICES = ["glue", "sso-admin"]

_NOT_FOUND = ("EntityNotFoundException", "Idc application not found. Need to create glue application first.")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """UpdateGlueIdentityCenterConfiguration replaces the stored Scopes while the account
    singleton exists, and raises EntityNotFoundException once it is deleted.

    Reference: https://docs.aws.amazon.com/glue/latest/webapi/API_UpdateGlueIdentityCenterConfiguration.html
    """
    glue = ctx.client("glue")
    instance_arn = _identity_center_instance_arn(ctx)

    existing = _refusal(lambda: glue.get_glue_identity_center_configuration())
    assert existing == _NOT_FOUND, (
        f"this account already has a Glue Identity Center configuration; refusing to "
        f"mutate an account-wide singleton that may be in real use (got {existing!r})"
    )

    app_arn = glue.create_glue_identity_center_configuration(
        InstanceArn=instance_arn, Scopes=["lakeformation:query"]
    )["ApplicationArn"]
    ctx.on_cleanup(lambda: _safe_delete_config(glue, app_arn))

    # Positive control: a real update against the live singleton replaces its Scopes.
    glue.update_glue_identity_center_configuration(Scopes=["lakeformation:query", "redshift:connect"])
    updated = glue.get_glue_identity_center_configuration()
    assert updated["ApplicationArn"] == app_arn, (
        f"expected ApplicationArn {app_arn!r} unchanged by update, got {updated.get('ApplicationArn')!r}"
    )
    assert sorted(updated["Scopes"]) == ["lakeformation:query", "redshift:connect"], (
        f"expected the updated Scopes, got {updated.get('Scopes')!r}"
    )

    glue.delete_glue_identity_center_configuration()

    # Negative: an identical update on the now-deleted singleton is refused, not silently
    # applied to nothing.
    after_delete = _refusal(lambda: glue.update_glue_identity_center_configuration(Scopes=["lakeformation:query"]))
    assert after_delete == _NOT_FOUND, f"expected the post-delete update to be refused, got {after_delete!r}"

    # Effect absent: an independent read (Get, not Update) confirms the singleton stays gone.
    get_after_delete = _refusal(lambda: glue.get_glue_identity_center_configuration())
    assert get_after_delete == _NOT_FOUND, (
        f"expected the deleted configuration to stay gone, got {get_after_delete!r}"
    )


def _refusal(fn):
    """Return the (code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe_delete_config(glue, app_arn) -> None:
    """Delete the Glue Identity Center configuration created as app_arn; tolerate it being gone."""
    try:
        glue.delete_glue_identity_center_configuration()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise
    assert app_arn, "app_arn must name the configuration this cleanup undoes"


def _identity_center_instance_arn(ctx) -> str:
    """The account's IAM Identity Center instance ARN; a standalone one this check creates is
    deleted again once the Glue configuration that depends on it is gone."""
    sso = ctx.client("sso-admin")
    instances = sso.list_instances().get("Instances", [])
    if instances:
        return instances[0]["InstanceArn"]

    instance_arn = sso.create_instance()["InstanceArn"]
    ctx.on_cleanup(lambda: sso.delete_instance(InstanceArn=instance_arn))

    deadline = time.monotonic() + 120.0
    status = None
    while time.monotonic() < deadline:
        status = sso.describe_instance(InstanceArn=instance_arn)["Status"]
        if status == "ACTIVE":
            return instance_arn
        if status in ("CREATE_FAILED", "DELETE_IN_PROGRESS"):
            raise AssertionError(f"IAM Identity Center instance in unexpected state: {status}")
        time.sleep(3)
    raise AssertionError(f"IAM Identity Center instance did not become ACTIVE in time (last status: {status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
