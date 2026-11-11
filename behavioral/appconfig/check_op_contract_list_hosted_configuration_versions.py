"""op-contract-listHostedConfigurationVersions."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-listHostedConfigurationVersions"
GROUP = "error-semantics"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-op-contract-list-hosted-configuration-versions"}


@tags("axis:happy-path", "cap:c2", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListHostedConfigurationVersions returns every created version, newest
    first, with correct content types and sizes; a nonexistent
    ConfigurationProfileId yields ResourceNotFoundException."""
    appconfig = ctx.client("appconfig")

    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS)["Id"]
    # Bottom-up teardown: AppConfig refuses DeleteApplication while a configuration profile
    # survives, and refuses DeleteConfigurationProfile while a hosted configuration version
    # survives. on_cleanup runs LIFO, so registering the profile/version deletes AFTER this one
    # makes them run first.
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))

    cp_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-behav-cp-"),
        LocationUri="hosted",
        Type="AWS.Freeform",
        Tags=_TAGS,
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=cp_id))

    body1 = b'{"a":1}'
    body2 = b'{"a":2,"b":3}'
    v1 = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=body1,
        ContentType="application/json",
    )["VersionNumber"]
    ctx.on_cleanup(
        lambda: appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=cp_id, VersionNumber=v1
        )
    )
    v2 = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Content=body2,
        ContentType="application/json",
    )["VersionNumber"]
    ctx.on_cleanup(
        lambda: appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=cp_id, VersionNumber=v2
        )
    )
    assert v2 == v1 + 1, "VersionNumber must auto-increment sequentially"

    resp = appconfig.list_hosted_configuration_versions(
        ApplicationId=app_id, ConfigurationProfileId=cp_id
    )
    items = resp["Items"]
    assert len(items) == 2, f"expected exactly 2 hosted configuration versions, got {len(items)}"
    # AppConfig returns hosted configuration versions newest-first.
    assert items[0]["VersionNumber"] == v2
    assert items[1]["VersionNumber"] == v1
    by_version = {item["VersionNumber"]: item for item in items}
    assert by_version[v1]["ContentType"] == "application/json"
    # ListHostedConfigurationVersions summaries do not carry a "Size" field
    # (that is only returned by GetHostedConfigurationVersion), so verify the
    # actual stored content length via a Get call for each version instead.
    got1 = appconfig.get_hosted_configuration_version(
        ApplicationId=app_id, ConfigurationProfileId=cp_id, VersionNumber=v1
    )
    got2 = appconfig.get_hosted_configuration_version(
        ApplicationId=app_id, ConfigurationProfileId=cp_id, VersionNumber=v2
    )
    assert len(got1["Content"].read()) == len(body1)
    assert len(got2["Content"].read()) == len(body2)

    err = _error(
        lambda: appconfig.list_hosted_configuration_versions(
            ApplicationId=app_id, ConfigurationProfileId="0000000"
        )
    )
    assert err["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err['Code']}"
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert err["Message"] == (
        f"Configuration Profile with Application Id {app_id} and Configuration Profile Id 0000000 "
        f"could not be found for account {account}."
    ), f"unexpected message: {err['Message']!r}"


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
