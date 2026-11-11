"""update-extension-description-length-exceeded-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-extension-description-length-exceeded-rejected"
GROUP = "server-side"
SERVICES = ["appconfig"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateExtension refuses a Description over 1024 characters with BadRequestException, leaving
    Description and VersionNumber unchanged; a valid Description then updates in place at version 1.
    """
    appconfig = ctx.client("appconfig")
    ext_id = _create_extension(ctx)
    original = appconfig.get_extension(ExtensionIdentifier=ext_id)
    assert original["VersionNumber"] == 1, f"expected version 1, got {original['VersionNumber']!r}"
    assert original["Description"] == "orig", f"expected 'orig', got {original['Description']!r}"

    too_long = "x" * 1025
    code, message = _error(
        lambda: appconfig.update_extension(ExtensionIdentifier=ext_id, Description=too_long)
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    expected = (
        f"1 validation error detected: Value '{too_long}' at 'description' failed to satisfy "
        f"constraint: Member must have length less than or equal to 1024"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    unchanged = appconfig.get_extension(ExtensionIdentifier=ext_id)
    assert unchanged["VersionNumber"] == 1, "rejected update must not have bumped the version"
    assert unchanged["Description"] == "orig", "rejected update must not have changed the description"

    fixed = appconfig.update_extension(ExtensionIdentifier=ext_id, Description="valid update")
    assert fixed["VersionNumber"] == 1, f"expected in-place version 1, got {fixed['VersionNumber']!r}"
    assert fixed["Description"] == "valid update", f"expected 'valid update', got {fixed['Description']!r}"

    after = appconfig.get_extension(ExtensionIdentifier=ext_id)
    assert after["VersionNumber"] == 1, f"expected version 1, got {after['VersionNumber']!r}"
    assert after["Description"] == "valid update", f"expected 'valid update', got {after['Description']!r}"



def _create_extension(ctx) -> str:
    appconfig = ctx.client("appconfig")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    default_bus_arn = f"arn:aws:events:{ctx.region}:{account_id}:event-bus/default"
    resp = appconfig.create_extension(
        Name=ctx.unique_name("sim2real-behav-ext-"),
        Description="orig",
        Actions={"ON_DEPLOYMENT_COMPLETE": [{"Name": "notify", "Uri": default_bus_arn}]},
    )
    ext_id = resp["Id"]
    ctx.on_cleanup(lambda: _safe_delete_extension(ctx, ext_id))
    return ext_id


def _safe_delete_extension(ctx, ext_id: str) -> None:
    appconfig = ctx.client("appconfig")
    try:
        appconfig.delete_extension(ExtensionIdentifier=ext_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
