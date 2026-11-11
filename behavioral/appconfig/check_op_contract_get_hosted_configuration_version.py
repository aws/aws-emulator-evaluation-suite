"""op-contract-getHostedConfigurationVersion."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-getHostedConfigurationVersion"
GROUP = "error-semantics"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "get-hosted-configuration-version-contract"}


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetHostedConfigurationVersion returns the exact stored bytes, ContentType, and
    VersionLabel for a specific version number; requesting a VersionNumber that was
    never created is rejected with ResourceNotFoundException."""
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

    content = b"key = value\nother = 42\n"
    version_number = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=content,
        ContentType="text/plain",
        VersionLabel="v1-behavioral",
    )["VersionNumber"]
    ctx.on_cleanup(
        lambda: appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version_number
        )
    )

    resp = appconfig.get_hosted_configuration_version(
        ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version_number
    )
    body = resp["Content"].read()
    assert body == content, f"expected stored content {content!r}, got {body!r}"
    assert resp["ContentType"] == "text/plain", (
        f"expected ContentType text/plain, got {resp['ContentType']!r}"
    )
    assert resp["VersionLabel"] == "v1-behavioral", (
        f"expected VersionLabel v1-behavioral, got {resp['VersionLabel']!r}"
    )

    # error boundary: VersionNumber never created for this profile
    code, code_msg = _error(
        lambda: appconfig.get_hosted_configuration_version(
            ApplicationId=app_id,
            ConfigurationProfileId=profile_id,
            VersionNumber=version_number + 41,
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert code_msg == (
        f"Hosted Configuration Version with Application Id {app_id}, Configuration Profile Id "
        f"{profile_id}, and Version {version_number + 41} could not be found for account {account}"
    ), f"unexpected message: {code_msg!r}"


def _error(fn):
    """Call fn(); return its botocore Error Code. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
