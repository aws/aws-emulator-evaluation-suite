"""extension-full-lifecycle-with-list."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "extension-full-lifecycle-with-list"
GROUP = "extension"
SERVICES = ["appconfig"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateExtension changes version 1 in place without bumping VersionNumber, visible via Get
    and List; after DeleteExtension, Get and Update fail with ResourceNotFoundException and List
    omits it.
    """
    appconfig = ctx.client("appconfig")
    name = ctx.unique_name("sim2real-ext-")
    action_uri = f"arn:aws:sns:{ctx.region}:{_account_id(ctx)}:sim2real-appconfig-ext-notify"

    created = appconfig.create_extension(
        Name=name,
        Description="v1",
        Actions={"ON_DEPLOYMENT_COMPLETE": [{"Name": "notify-complete", "Uri": action_uri}]},
        Tags={"sim2real": CHECK},
    )
    ext_id = created["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appconfig.delete_extension(ExtensionIdentifier=ext_id)))
    assert created["VersionNumber"] == 1, f"expected initial VersionNumber 1, got {created['VersionNumber']}"

    got = appconfig.get_extension(ExtensionIdentifier=ext_id)
    assert got["Name"] == name
    assert got["VersionNumber"] == 1
    assert got["Actions"]["ON_DEPLOYMENT_COMPLETE"][0]["Name"] == "notify-complete"

    updated = appconfig.update_extension(
        ExtensionIdentifier=ext_id,
        VersionNumber=1,
        Description="v2",
        Actions={"ON_DEPLOYMENT_COMPLETE": [{"Name": "notify-complete-v2", "Uri": action_uri}]},
    )
    assert updated["VersionNumber"] == 1, f"UpdateExtension must not bump VersionNumber, got {updated['VersionNumber']}"
    assert updated["Description"] == "v2"

    got_v2 = appconfig.get_extension(ExtensionIdentifier=ext_id)
    assert got_v2["VersionNumber"] == 1
    assert got_v2["Actions"]["ON_DEPLOYMENT_COMPLETE"][0]["Name"] == "notify-complete-v2"

    listing = appconfig.list_extensions(Name=name)["Items"]
    matches = [item for item in listing if item["Id"] == ext_id]
    assert len(matches) == 1, f"expected exactly one listed extension with id {ext_id}, got {matches}"
    assert matches[0]["VersionNumber"] == 1

    appconfig.delete_extension(ExtensionIdentifier=ext_id)

    not_found = f"Extension could not be found for account {_account_id(ctx)}."
    err = _client_error(lambda: appconfig.get_extension(ExtensionIdentifier=ext_id))
    assert err["Code"] == "ResourceNotFoundException", f"expected 404 after delete, got {err['Code']}"
    assert err["Message"] == not_found, f"expected message {not_found!r}, got {err['Message']!r}"

    listing_after = appconfig.list_extensions(Name=name)["Items"]
    assert not any(item["Id"] == ext_id for item in listing_after), "deleted extension still listed"

    update_err = _client_error(
        lambda: appconfig.update_extension(ExtensionIdentifier=ext_id, Description="v3")
    )
    assert update_err["Code"] == "ResourceNotFoundException", (
        f"expected UpdateExtension on a deleted extension to 404, got {update_err['Code']}"
    )
    assert update_err["Message"] == not_found, f"expected message {not_found!r}, got {update_err['Message']!r}"


def _client_error(fn):
    """Call fn() and return its ClientError's Error dict; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _ignore_not_found(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
