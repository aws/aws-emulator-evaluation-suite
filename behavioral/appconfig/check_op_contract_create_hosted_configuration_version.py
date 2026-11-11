"""op-contract-createHostedConfigurationVersion."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-createHostedConfigurationVersion"
GROUP = "error-semantics"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-create-hosted-configuration-version-contract"}


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateHostedConfigurationVersion stores content byte-for-byte at VersionNumber 1;
    content over the 1 MB limit is rejected with PayloadTooLargeException and no version
    is persisted."""
    appconfig = ctx.client("appconfig")

    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))

    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-cp-"),
        LocationUri="hosted",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_configuration_profile(
            ApplicationId=app_id, ConfigurationProfileId=profile_id
        )
    )

    content = b'{"feature":"on"}'
    resp = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=content,
        ContentType="application/json",
        Description="initial version",
    )
    version_number = resp["VersionNumber"]
    ctx.on_cleanup(
        lambda: appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id,
            ConfigurationProfileId=profile_id,
            VersionNumber=version_number,
        )
    )

    assert version_number == 1, f"expected first VersionNumber == 1, got {version_number}"
    assert resp["ContentType"] == "application/json", (
        f"expected ContentType application/json, got {resp['ContentType']!r}"
    )
    got_content = resp["Content"].read()
    assert got_content == content, f"content mismatch: expected {content!r}, got {got_content!r}"

    # error boundary: content exceeding the 1 MB hosted-store limit. Use a size well
    # past the documented 1 MB boundary (rather than 1 MB + 1 byte) so the check does
    # not depend on the exact byte-accounting AWS applies at the boundary.
    oversized = b"a" * (5 * 1024 * 1024)
    code, message = _error(
        lambda: appconfig.create_hosted_configuration_version(
            ApplicationId=app_id,
            ConfigurationProfileId=profile_id,
            Content=oversized,
            ContentType="text/plain",
        )
    )
    assert code == "PayloadTooLargeException", f"expected PayloadTooLargeException, got {code}"
    assert message == "Content size limit exceeded.", (
        f"expected message 'Content size limit exceeded.', got {message!r}"
    )

    # the rejected call must not have created VersionNumber 2
    versions = appconfig.list_hosted_configuration_versions(
        ApplicationId=app_id, ConfigurationProfileId=profile_id
    )["Items"]
    got_versions = [v["VersionNumber"] for v in versions]
    assert got_versions == [1], f"expected only VersionNumber [1] to persist, got {got_versions}"


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of its ClientError. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
