"""update-extension-association-wrong-resource-type-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-extension-association-wrong-resource-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-update-extension-association"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateExtensionAssociation supplying parameters that drop a value for a
    Required parameter declared by the extension's parameter schema is rejected
    with BadRequestException, not silently coerced or accepted."""
    appconfig = ctx.client("appconfig")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    ext_id, ext_version = _create_extension(ctx, account_id)
    app_id = _create_application(ctx)
    app_arn = f"arn:aws:appconfig:{ctx.region}:{account_id}:application/{app_id}"

    assoc = appconfig.create_extension_association(
        ExtensionIdentifier=ext_id,
        ExtensionVersionNumber=ext_version,
        ResourceIdentifier=app_arn,
        Parameters={"RequiredParam": "initial-value"},
        Tags=_TAGS,
    )
    assoc_id = assoc["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_extension_association(ExtensionAssociationId=assoc_id))

    def _drop_required_param():
        appconfig.update_extension_association(
            ExtensionAssociationId=assoc_id,
            Parameters={"OptionalParam": "opt-value"},
        )

    code, message = _error(_drop_required_param)
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    # AWS renders two spaces after the parameter name.
    expected = (
        f"Parameter RequiredParam  is required for extension {ext_id} version {ext_version}, "
        f"but a value has not been supplied."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the association's parameters were not changed by the rejected update.
    unchanged = appconfig.get_extension_association(ExtensionAssociationId=assoc_id)
    assert unchanged["Parameters"] == {"RequiredParam": "initial-value"}, (
        f"expected Parameters unchanged at {{'RequiredParam': 'initial-value'}}, "
        f"got {unchanged['Parameters']!r}"
    )

    # Positive control: an update that still supplies the required parameter succeeds.
    appconfig.update_extension_association(
        ExtensionAssociationId=assoc_id,
        Parameters={"RequiredParam": "updated-value", "OptionalParam": "opt-value"},
    )
    updated = appconfig.get_extension_association(ExtensionAssociationId=assoc_id)
    expected = {"RequiredParam": "updated-value", "OptionalParam": "opt-value"}
    assert updated["Parameters"] == expected, f"expected {expected!r}, got {updated['Parameters']!r}"


def _error(fn) -> tuple[str, str | None]:
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_extension(ctx, account_id: str) -> tuple[str, int]:
    appconfig = ctx.client("appconfig")
    # Use the account's default EventBridge event bus as the action target: it
    # always exists in-account and needs no extra resource provisioning or
    # cross-account permission grant (unlike an SNS topic/SQS queue/Lambda ARN).
    ext = appconfig.create_extension(
        Name=ctx.unique_name("sim2real-ext-"),
        Actions={
            "ON_DEPLOYMENT_COMPLETE": [
                {
                    "Name": "notify",
                    "Uri": f"arn:aws:events:{ctx.region}:{account_id}:event-bus/default",
                }
            ]
        },
        Parameters={
            "RequiredParam": {"Required": True},
            "OptionalParam": {"Required": False},
        },
        Tags=_TAGS,
    )
    ext_id = ext["Id"]
    ext_version = ext["VersionNumber"]
    ctx.on_cleanup(lambda: appconfig.delete_extension(ExtensionIdentifier=ext_id))
    return ext_id, ext_version


def _create_application(ctx) -> str:
    appconfig = ctx.client("appconfig")
    app = appconfig.create_application(Name=ctx.unique_name("sim2real-app-"), Tags=_TAGS)
    app_id = app["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    return app_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
