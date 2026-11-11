"""extension-update-fields-persist."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "extension-update-fields-persist"
GROUP = "state-machine"
SERVICES = ["appconfig"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateExtension changes description and actions in place: VersionNumber stays the same and an
    unpinned GetExtension returns the updated values, not the creation-time ones.
    """
    appconfig = ctx.client("appconfig")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-ext-")
    fake_uri = f"arn:aws:sns:{ctx.region}:{account_id}:{ctx.unique_name('sim2real-topic-')}"

    created = appconfig.create_extension(
        Name=name,
        Description="version 1 description",
        Actions={"ON_DEPLOYMENT_START": [{"Name": "notify-v1", "Uri": fake_uri}]},
    )
    ext_id = created["Id"]
    ctx.on_cleanup(lambda: _safe_delete_extension(appconfig, ext_id))
    version1 = created["VersionNumber"]
    assert created["Description"] == "version 1 description", (
        f"expected creation-time description echoed, got {created['Description']!r}"
    )

    updated = appconfig.update_extension(
        ExtensionIdentifier=ext_id,
        Description="version 2 description",
        Actions={"ON_DEPLOYMENT_START": [{"Name": "notify-v2", "Uri": fake_uri}]},
    )
    assert updated["VersionNumber"] == version1, (
        f"UpdateExtension must not fork a new version, expected {version1}, got {updated['VersionNumber']}"
    )
    assert updated["Description"] == "version 2 description", (
        f"expected updated description in the UpdateExtension response, got {updated['Description']!r}"
    )
    assert updated["Actions"]["ON_DEPLOYMENT_START"][0]["Name"] == "notify-v2", (
        f"expected updated action name in the UpdateExtension response, got {updated['Actions']}"
    )

    latest = appconfig.get_extension(ExtensionIdentifier=ext_id)
    assert latest["VersionNumber"] == version1, (
        f"GetExtension with no version pinned must still report version {version1}, "
        f"got {latest['VersionNumber']}"
    )
    assert latest["Description"] == "version 2 description", (
        f"expected GetExtension to reflect the persisted update, got {latest['Description']!r}"
    )
    assert latest["Actions"]["ON_DEPLOYMENT_START"][0]["Name"] == "notify-v2", (
        f"expected GetExtension to reflect the persisted action update, got {latest['Actions']}"
    )
    # No creation-time values leak through after the update.
    assert latest["Description"] != "version 1 description", (
        "creation-time description leaked through after UpdateExtension"
    )
    assert latest["Actions"]["ON_DEPLOYMENT_START"][0]["Name"] != "notify-v1", (
        "creation-time action name leaked through after UpdateExtension"
    )

    # Explicitly pinning the original version number also returns the updated fields --
    # AppConfig extensions mutate in place rather than forking per-version history.
    pinned_original = appconfig.get_extension(ExtensionIdentifier=ext_id, VersionNumber=version1)
    assert pinned_original["VersionNumber"] == version1, (
        f"pinning VersionNumber={version1} must echo that version, got {pinned_original['VersionNumber']}"
    )
    assert pinned_original["Description"] == "version 2 description", (
        f"pinning the original version number must still return the in-place update, "
        f"got {pinned_original['Description']!r}"
    )

    # The delete this check already performs at cleanup is a free negative -- prove it
    # actually lands and that the dead id stops resolving to both a read and a mutation,
    # rather than leaving the teardown entirely unasserted.
    appconfig.delete_extension(ExtensionIdentifier=ext_id)
    not_found = (
        "ResourceNotFoundException",
        f"Extension could not be found for account {account_id}.",
    )
    got = _error(lambda: appconfig.get_extension(ExtensionIdentifier=ext_id))
    assert got == not_found, (
        f"expected GetExtension on a deleted extension to fail with {not_found!r}, got {got!r}"
    )
    got = _error(
        lambda: appconfig.update_extension(ExtensionIdentifier=ext_id, Description="post-delete")
    )
    assert got == not_found, (
        f"expected UpdateExtension on a deleted extension to fail with {not_found!r}, got {got!r}"
    )


def _error(fn):
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to fail, but it succeeded")


def _safe_delete_extension(appconfig, ext_id):
    try:
        appconfig.delete_extension(ExtensionIdentifier=ext_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
