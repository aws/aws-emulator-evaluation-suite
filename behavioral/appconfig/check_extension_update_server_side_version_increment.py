"""extension-update-server-side-version-increment."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "extension-update-server-side-version-increment"
GROUP = "server-side"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-extension-update-version-increment"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateExtension never increments VersionNumber: with or without the current version as a
    lock token, and whether it changes Description or Actions, the extension stays at version 1."""
    appconfig = ctx.client("appconfig")
    ext_id, bus_arn = _create_extension(ctx)

    created = appconfig.get_extension(ExtensionIdentifier=ext_id)
    assert created["VersionNumber"] == 1, f"expected freshly-created extension at version 1, got {created['VersionNumber']}"

    updated1 = appconfig.update_extension(ExtensionIdentifier=ext_id, Description="first update")
    assert updated1["VersionNumber"] == 1, (
        f"expected version to stay at 1 when VersionNumber is omitted, got {updated1['VersionNumber']}"
    )
    got1 = appconfig.get_extension(ExtensionIdentifier=ext_id)
    assert got1["VersionNumber"] == 1, f"independent read: expected version 1, got {got1['VersionNumber']}"
    assert got1["Description"] == "first update", f"independent read: expected persisted description, got {got1['Description']!r}"

    updated2 = appconfig.update_extension(
        ExtensionIdentifier=ext_id,
        Actions={"ON_DEPLOYMENT_COMPLETE": [{"Name": "notify-v2", "Uri": bus_arn}]},
        VersionNumber=1,
    )
    assert updated2["VersionNumber"] == 1, (
        f"expected version to stay at 1 even after a structural change with a matching "
        f"VersionNumber lock, got {updated2['VersionNumber']}"
    )
    got2 = appconfig.get_extension(ExtensionIdentifier=ext_id)
    assert got2["VersionNumber"] == 1, f"independent read: expected version to stay at 1, got {got2['VersionNumber']}"
    assert got2["Actions"]["ON_DEPLOYMENT_COMPLETE"][0]["Name"] == "notify-v2", (
        f"independent read: expected the structural Actions change to have landed, got {got2['Actions']}"
    )




def _create_extension(ctx):
    appconfig = ctx.client("appconfig")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    default_bus_arn = f"arn:aws:events:{ctx.region}:{account_id}:event-bus/default"
    resp = appconfig.create_extension(
        Name=ctx.unique_name("sim2real-behav-ext-"),
        Actions={"ON_DEPLOYMENT_COMPLETE": [{"Name": "notify", "Uri": default_bus_arn}]},
        Tags=_TAGS,
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

