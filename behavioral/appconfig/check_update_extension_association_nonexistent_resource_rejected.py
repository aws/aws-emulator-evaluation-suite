"""update-extension-association-nonexistent-resource-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-extension-association-nonexistent-resource-rejected"
GROUP = "overly-permissive"
SERVICES = ["appconfig"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateExtensionAssociation targeting an association id that does not exist is
    rejected with ResourceNotFoundException rather than silently no-op'ing, while the
    same call against the real association succeeds and actually persists the change."""
    appconfig = ctx.client("appconfig")
    app_id = _create_application(ctx)
    ext_id, ext_arn = _create_extension(ctx)
    app_arn = _application_arn(ctx, app_id)
    assoc_id = _create_extension_association(ctx, ext_id, app_arn)

    bogus_association_id = "0000000"  # well-formed [a-z0-9]{4,7} id that was never issued
    assert bogus_association_id != assoc_id, "fixture bug: bogus id collided with the real one"

    before_bogus = appconfig.get_extension_association(ExtensionAssociationId=assoc_id)

    code, message = _error(
        lambda: appconfig.update_extension_association(
            ExtensionAssociationId=bogus_association_id, Parameters={"mode": "bogus-write"}
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = f"ExtensionAssociation could not be found for account {ctx.account}."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the real association is unchanged by the bogus call (ResponseMetadata,
    # which carries a fresh request id and timestamp on every call, is not part of the state)
    after_bogus = appconfig.get_extension_association(ExtensionAssociationId=assoc_id)
    before_state = {k: v for k, v in before_bogus.items() if k != "ResponseMetadata"}
    after_state = {k: v for k, v in after_bogus.items() if k != "ResponseMetadata"}
    assert after_state == before_state, (
        f"bogus update mutated the real association: before={before_state!r} after={after_state!r}"
    )

    # positive control: updating the real association id succeeds and persists
    appconfig.update_extension_association(
        ExtensionAssociationId=assoc_id, Parameters={"mode": "active"}
    )
    real_after = appconfig.get_extension_association(ExtensionAssociationId=assoc_id)
    assert real_after["Parameters"]["mode"] == "active", (
        f"expected persisted mode=active, got {real_after.get('Parameters')}"
    )


_PREFIX = "sim2real-appconfig-"
_TAGS = {"sim2real:managed": "true", "sim2real": CHECK}


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_application(ctx):
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(
        Name=ctx.unique_name(_PREFIX + "app-"), Tags=_TAGS
    )["Id"]

    def _cleanup():
        try:
            appconfig.delete_application(ApplicationId=app_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return app_id


def _application_arn(ctx, app_id):
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    return f"arn:aws:appconfig:{ctx.region}:{account_id}:application/{app_id}"


def _create_extension(ctx):
    appconfig = ctx.client("appconfig")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    default_bus_arn = f"arn:aws:events:{ctx.region}:{account_id}:event-bus/default"
    resp = appconfig.create_extension(
        Name=ctx.unique_name(_PREFIX + "ext-"),
        Actions={"ON_DEPLOYMENT_START": [{"Name": "notify", "Uri": default_bus_arn}]},
        Parameters={"mode": {"Description": "operating mode", "Required": False}},
        Tags=_TAGS,
    )
    ext_id = resp["Id"]
    ext_arn = resp["Arn"]

    def _cleanup():
        try:
            appconfig.delete_extension(ExtensionIdentifier=ext_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return ext_id, ext_arn


def _create_extension_association(ctx, ext_id, resource_arn):
    appconfig = ctx.client("appconfig")
    resp = appconfig.create_extension_association(
        ExtensionIdentifier=ext_id, ResourceIdentifier=resource_arn, Tags=_TAGS
    )
    assoc_id = resp["Id"]

    def _cleanup():
        try:
            appconfig.delete_extension_association(ExtensionAssociationId=assoc_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return assoc_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
