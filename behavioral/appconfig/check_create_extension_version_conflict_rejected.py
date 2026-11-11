"""create-extension-version-conflict-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-extension-version-conflict-rejected"
GROUP = "data-plane"
SERVICES = ["appconfig"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateExtension for an existing Name with a wrong LatestVersionNumber is rejected with ConflictException and
    creates no version (GetExtension still reports 1), while the correct LatestVersionNumber creates version 2."""
    appconfig = ctx.client("appconfig")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-behav-ext-")
    uri = f"arn:aws:sns:{ctx.region}:{account_id}:sim2real-behav-topic"


    first_version = appconfig.create_extension(
        Name=name, Actions={"ON_DEPLOYMENT_COMPLETE": [{"Name": "notify", "Uri": uri}]}
    )
    extension_id = first_version["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_extension(ExtensionIdentifier=extension_id))
    assert first_version["VersionNumber"] == 1, (
        f"positive control: expected the first CreateExtension to land on version 1, "
        f"got {first_version['VersionNumber']!r}"
    )

    code, message = _error(
        lambda: appconfig.create_extension(
            Name=name,
            Actions={"ON_DEPLOYMENT_COMPLETE": [{"Name": "notify", "Uri": uri}]},
            LatestVersionNumber=99,
        )
    )
    assert code == "ConflictException", (
        f"CreateExtension with a stale LatestVersionNumber=99 should be rejected with "
        f"ConflictException, got {code!r}"
    )
    expected = "LatestVersionNumber supplied in request 99 does not match latest version 1."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: still only version 1 exists.
    still_v1 = appconfig.get_extension(ExtensionIdentifier=extension_id)
    assert still_v1["VersionNumber"] == 1, (
        f"the rejected CreateExtension(LatestVersionNumber=99) must not create a new "
        f"version: expected GetExtension to still report version 1, got "
        f"{still_v1['VersionNumber']!r}"
    )

    # Positive control: the correct LatestVersionNumber (1) succeeds and bumps the version
    # to a new value strictly greater than the last confirmed version (identical content
    # with a matching LatestVersionNumber is a no-op on some backends, so change the
    # action's Description to guarantee a real new version is written).
    second_version = appconfig.create_extension(
        Name=name,
        Actions={"ON_DEPLOYMENT_COMPLETE": [{"Name": "notify", "Description": "v2", "Uri": uri}]},
        LatestVersionNumber=1,
    )

    assert second_version["Id"] == extension_id, (
        f"CreateExtension with the correct LatestVersionNumber=1 should add a version to "
        f"the same extension {extension_id!r}, got Id {second_version['Id']!r}"
    )
    assert second_version["VersionNumber"] > still_v1["VersionNumber"], (
        f"the restored call should bump the version past the last confirmed version "
        f"{still_v1['VersionNumber']!r}, got {second_version['VersionNumber']!r}"
    )

    latest = appconfig.get_extension(ExtensionIdentifier=extension_id)
    assert latest["VersionNumber"] == second_version["VersionNumber"], (
        f"an independent GetExtension should report the version just created "
        f"({second_version['VersionNumber']!r}), got {latest['VersionNumber']!r}"
    )




def _error(fn):
    """Call fn(); return its botocore (error code, error message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available and must not be
    reported as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
