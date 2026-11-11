"""update-extension-version-increments-and-is-gettable."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-extension-version-increments-and-is-gettable"
GROUP = "state-machine"
SERVICES = ["appconfig"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateExtension with an existing Name increments VersionNumber and GetExtension returns each
    version's content, while UpdateExtension edits the current version without a new number.
    """
    appconfig = ctx.client("appconfig")

    name = ctx.unique_name("sim2real-ext-")
    action_uri = _sns_topic_arn(ctx)
    created = appconfig.create_extension(
        Name=name,
        Description="v1 description",
        Actions={"ON_DEPLOYMENT_COMPLETE": [{"Name": "noop-action", "Uri": action_uri}]},
        Tags={"sim2real": CHECK},
    )
    ext_id = created["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_extension(ExtensionIdentifier=ext_id))
    assert created["VersionNumber"] == 1, f"expected initial version 1, got {created['VersionNumber']}"
    assert created["Description"] == "v1 description", f"got {created['Description']!r}"

    # UpdateExtension edits the current (latest) version's attributes in place; it must
    # not create a new version.
    in_place = appconfig.update_extension(
        ExtensionIdentifier=ext_id,
        Description="v1 description (edited)",
    )
    assert in_place["VersionNumber"] == 1, "UpdateExtension must not bump the version number"
    assert in_place["Description"] == "v1 description (edited)", f"got {in_place['Description']!r}"

    # A new version is created by calling CreateExtension again with the same Name. Real
    # AWS requires LatestVersionNumber to be set to the current latest version number in
    # this case (it is only optional for the very first CreateExtension call for a given
    # Name); omitting it fails with a BadRequestException.
    created_v2 = appconfig.create_extension(
        Name=name,
        Description="v2 description",
        Actions={"ON_DEPLOYMENT_COMPLETE": [{"Name": "noop-action-v2", "Uri": action_uri}]},
        LatestVersionNumber=created["VersionNumber"],
        Tags={"sim2real": CHECK},
    )
    assert created_v2["Id"] == ext_id, f"expected same extension id {ext_id!r}, got {created_v2['Id']!r}"
    assert created_v2["VersionNumber"] == 2, f"expected version to increment to 2, got {created_v2['VersionNumber']}"
    assert created_v2["Description"] == "v2 description", f"got {created_v2['Description']!r}"

    latest = appconfig.get_extension(ExtensionIdentifier=ext_id)
    assert latest["VersionNumber"] == 2, f"expected GetExtension to default to latest version 2, got {latest['VersionNumber']}"
    assert latest["Description"] == "v2 description", f"got {latest['Description']!r}"
    assert latest["Actions"]["ON_DEPLOYMENT_COMPLETE"][0]["Name"] == "noop-action-v2", (
        f"got {latest['Actions']['ON_DEPLOYMENT_COMPLETE'][0]['Name']!r}"
    )

    original = appconfig.get_extension(ExtensionIdentifier=ext_id, VersionNumber=1)
    assert original["VersionNumber"] == 1, f"expected version 1, got {original['VersionNumber']}"
    assert original["Description"] == "v1 description (edited)", (
        "version 1 content should reflect the earlier in-place UpdateExtension call"
    )
    assert original["Actions"]["ON_DEPLOYMENT_COMPLETE"][0]["Name"] == "noop-action", (
        "version 1's Actions must remain unmutated by the v2 create, since the earlier "
        f"UpdateExtension only touched Description; got {original['Actions']['ON_DEPLOYMENT_COMPLETE'][0]['Name']!r}"
    )


def _sns_topic_arn(ctx) -> str:
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    return f"arn:aws:sns:{ctx.region}:{account_id}:{ctx.unique_name('sim2real-topic-')}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

