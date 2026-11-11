"""update-extension-version-increments-on-change."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-extension-version-increments-on-change"
GROUP = "server-side"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-update-extension-version-increments-on-change"}
_SNS_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real", "Value": "appconfig-update-extension-version-increments-on-change"},
]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateExtension patches the latest version in place (VersionNumber stays 1), while
    CreateExtension re-issued with LatestVersionNumber creates version 2, leaving version 1 intact.

    Reference: https://docs.aws.amazon.com/appconfig/2019-10-09/APIReference/API_UpdateExtension.html
    """
    appconfig = ctx.client("appconfig")
    sns = ctx.client("sns")

    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-behav-topic-"), Tags=_SNS_TAGS)["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    name = ctx.unique_name("sim2real-behav-ext-")
    actions = {"ON_DEPLOYMENT_COMPLETE": [{"Name": "notify", "Uri": topic_arn}]}
    created = appconfig.create_extension(Name=name, Actions=actions, Description="v1", Tags=_TAGS)
    ext_id = created["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_extension(ExtensionIdentifier=ext_id))
    assert created["VersionNumber"] == 1, f"expected initial version 1, got {created['VersionNumber']}"
    assert created["Actions"]["ON_DEPLOYMENT_COMPLETE"][0]["Name"] == "notify", (
        f"expected initial action name 'notify', got {created['Actions']}"
    )

    # The API reference's UpdateExtension sample response also stays at VersionNumber 1.
    updated = appconfig.update_extension(ExtensionIdentifier=ext_id, Description="v2")
    assert updated["VersionNumber"] == 1, f"expected in-place version 1, got {updated['VersionNumber']}"
    assert updated["Description"] == "v2", f"expected description 'v2', got {updated['Description']!r}"

    latest = appconfig.get_extension(ExtensionIdentifier=ext_id)
    assert latest["VersionNumber"] == 1, f"expected latest version to stay 1, got {latest['VersionNumber']}"
    assert latest["Description"] == "v2", f"expected latest description 'v2', got {latest['Description']!r}"

    same_version = appconfig.get_extension(ExtensionIdentifier=ext_id, VersionNumber=1)
    assert same_version["Description"] == "v2", "in-place update must be visible on version 1 itself"

    # CreateExtension on the same Name with LatestVersionNumber=<current> is the
    # version-increment primitive.
    recreated = appconfig.create_extension(
        Name=name, Actions=actions, Description="v3", LatestVersionNumber=1, Tags=_TAGS
    )
    assert recreated["VersionNumber"] == 2, f"expected new version 2, got {recreated['VersionNumber']}"
    assert recreated["Description"] == "v3", f"expected description 'v3', got {recreated['Description']!r}"

    newest = appconfig.get_extension(ExtensionIdentifier=ext_id)
    assert newest["VersionNumber"] == 2, f"expected newest version 2, got {newest['VersionNumber']}"
    assert newest["Description"] == "v3", f"expected newest description 'v3', got {newest['Description']!r}"

    preserved_v1 = appconfig.get_extension(ExtensionIdentifier=ext_id, VersionNumber=1)
    assert preserved_v1["VersionNumber"] == 1, f"expected preserved version 1, got {preserved_v1['VersionNumber']}"
    assert preserved_v1["Description"] == "v2", "version 1's content must remain unmutated by the v2 create"
    assert preserved_v1["Actions"]["ON_DEPLOYMENT_COMPLETE"][0]["Name"] == "notify", (
        f"expected version 1's action name to remain 'notify', got {preserved_v1['Actions']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
