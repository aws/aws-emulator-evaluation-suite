"""delete-extension-with-active-association-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-extension-with-active-association-rejected"
GROUP = "error-semantics"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-delete-extension-with-active-association-rejected"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting an extension with an active association is rejected rather than cascading."""
    appconfig = ctx.client("appconfig")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    ext_name = ctx.unique_name("sim2real-ext-")
    # The action is never invoked in this check (no deployment is started), so a
    # syntactically valid SNS topic ARN that AppConfig never needs to call is sufficient --
    # it only has to satisfy CreateExtension's requirement that every action have a Uri.
    action_uri = _sns_topic_arn(ctx)
    ext = appconfig.create_extension(
        Name=ext_name,
        Actions={"ON_DEPLOYMENT_COMPLETE": [{"Name": "noop-action", "Uri": action_uri}]},
        Tags=_TAGS,
    )
    ext_id = ext["Id"]
    ctx.on_cleanup(_unless_gone(lambda: appconfig.delete_extension(ExtensionIdentifier=ext_id)))

    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    app_arn = _app_arn(ctx, app_id)

    assoc = appconfig.create_extension_association(
        ExtensionIdentifier=ext_id, ResourceIdentifier=app_arn, Tags=_TAGS
    )
    assoc_id = assoc["Id"]

    # Negative: deleting the extension while it still has an active association must be rejected.
    code, message = _client_error(lambda: appconfig.delete_extension(ExtensionIdentifier=ext_id))
    assert code == "BadRequestException", (
        f"expected BadRequestException with active association, got {code!r}"
    )
    expected = (
        f"Cannot delete extension {ext_id}, version 1, for account {account_id}, as there are "
        f"1 associations of the extension still existing."
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # The extension must still exist untouched by the rejected call.
    still_there = appconfig.get_extension(ExtensionIdentifier=ext_id)
    assert still_there["Id"] == ext_id, (
        f"expected the rejected delete to leave extension {ext_id} in place, got {still_there!r}"
    )

    # Positive control: after removing the association, the identical delete call succeeds.
    appconfig.delete_extension_association(ExtensionAssociationId=assoc_id)
    appconfig.delete_extension(ExtensionIdentifier=ext_id)
    code_after, message_after = _client_error(
        lambda: appconfig.get_extension(ExtensionIdentifier=ext_id)
    )
    assert code_after == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for the deleted extension {ext_id}, "
        f"got {code_after!r}"
    )
    not_found = f"Extension could not be found for account {account_id}."
    assert message_after == not_found, f"expected {not_found!r}, got {message_after!r}"


def _client_error(fn):
    """Call fn(); return (code, message) of its botocore ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _unless_gone(fn):
    """Teardown wrapper: a resource the check already deleted is not a teardown failure."""

    def _run():
        try:
            fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise

    return _run


def _app_arn(ctx, app_id: str) -> str:
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    return f"arn:aws:appconfig:{ctx.region}:{account_id}:application/{app_id}"


def _sns_topic_arn(ctx) -> str:
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    return f"arn:aws:sns:{ctx.region}:{account_id}:{ctx.unique_name('sim2real-topic-')}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
