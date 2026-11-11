"""update-extension-stale-version-conflict-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-extension-stale-version-conflict-rejected"
GROUP = "server-side"
SERVICES = ["appconfig"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateExtension with a VersionNumber matching no existing version raises
    ResourceNotFoundException and leaves Actions and VersionNumber unchanged; an update with the
    current version succeeds.
    """
    appconfig = ctx.client("appconfig")
    ext_id, bus_arn = _create_extension(ctx)

    created = appconfig.get_extension(ExtensionIdentifier=ext_id)
    assert created["VersionNumber"] == 1

    # Mismatched lock: actual current version is 1, but we claim a version that has
    # never existed for this extension.
    code, message = _error(
        lambda: appconfig.update_extension(
            ExtensionIdentifier=ext_id,
            Actions={"ON_DEPLOYMENT_COMPLETE": [{"Name": "attempted-stale", "Uri": bus_arn}]},
            VersionNumber=5,
        )
    )
    assert code == "ResourceNotFoundException", f"got={code}"
    expected = f"Extension could not be found for account {ctx.account}."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the extension must be untouched by the rejected call.
    unchanged = appconfig.get_extension(ExtensionIdentifier=ext_id)
    assert unchanged["VersionNumber"] == 1, "rejected update must not have changed the version"
    assert unchanged["Actions"]["ON_DEPLOYMENT_COMPLETE"][0]["Name"] == "notify", (
        "rejected update must not have changed the Actions"
    )

    # Positive control: same extension, correct current version, succeeds.
    fixed = appconfig.update_extension(
        ExtensionIdentifier=ext_id,
        Actions={"ON_DEPLOYMENT_COMPLETE": [{"Name": "notify-v2", "Uri": bus_arn}]},
        VersionNumber=1,
    )
    assert fixed["VersionNumber"] == 1
    assert fixed["Actions"]["ON_DEPLOYMENT_COMPLETE"][0]["Name"] == "notify-v2"

    # Terminal read independent of the mutating call: the restored update is visible
    # through GetExtension, not just echoed back by UpdateExtension's own response.
    confirmed = appconfig.get_extension(ExtensionIdentifier=ext_id)
    assert confirmed["VersionNumber"] == 1
    assert confirmed["Actions"]["ON_DEPLOYMENT_COMPLETE"][0]["Name"] == "notify-v2", (
        "independent read must reflect the restored update"
    )





def _create_extension(ctx):
    appconfig = ctx.client("appconfig")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    default_bus_arn = f"arn:aws:events:{ctx.region}:{account_id}:event-bus/default"
    resp = appconfig.create_extension(
        Name=ctx.unique_name("sim2real-behav-ext-"),
        Actions={"ON_DEPLOYMENT_COMPLETE": [{"Name": "notify", "Uri": default_bus_arn}]},
    )
    ext_id = resp["Id"]
    ctx.on_cleanup(lambda: _safe_delete_extension(ctx, ext_id))
    return ext_id, default_bus_arn


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
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
