"""op-contract-deleteHostedConfigurationVersion."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteHostedConfigurationVersion"
GROUP = "error-semantics"
SERVICES = ["appconfig"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteHostedConfigurationVersion removes the version (positive control); a second
    delete on the now-absent version is rejected with ResourceNotFoundException and the
    version stays absent from ListHostedConfigurationVersions."""
    appconfig = ctx.client("appconfig")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-app-"))["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))

    profile_id = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name=ctx.unique_name("sim2real-cp-"),
        LocationUri="hosted",
    )["Id"]
    ctx.on_cleanup(
        lambda: appconfig.delete_configuration_profile(
            ApplicationId=app_id, ConfigurationProfileId=profile_id
        )
    )

    version_number = appconfig.create_hosted_configuration_version(
        ApplicationId=app_id,
        ConfigurationProfileId=profile_id,
        Content=b'{"k":"v"}',
        ContentType="application/json",
    )["VersionNumber"]

    # positive control: version exists before deletion
    before = appconfig.list_hosted_configuration_versions(
        ApplicationId=app_id, ConfigurationProfileId=profile_id
    )["Items"]
    assert any(v["VersionNumber"] == version_number for v in before), (
        f"expected version {version_number} in {before!r}"
    )

    appconfig.delete_hosted_configuration_version(
        ApplicationId=app_id, ConfigurationProfileId=profile_id, VersionNumber=version_number
    )

    # AWS ends this message without a trailing period.
    not_found = (
        f"Hosted Configuration Version with Application Id {app_id}, Configuration Profile Id "
        f"{profile_id}, and Version {version_number} could not be found for account {account_id}"
    )
    code, message = _client_error(
        lambda: appconfig.get_hosted_configuration_version(
            ApplicationId=app_id,
            ConfigurationProfileId=profile_id,
            VersionNumber=version_number,
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == not_found, f"expected {not_found!r}, got {message!r}"
    after = appconfig.list_hosted_configuration_versions(
        ApplicationId=app_id, ConfigurationProfileId=profile_id
    )["Items"]
    assert all(v["VersionNumber"] != version_number for v in after), (
        f"deleted version {version_number} still listed in {after!r}"
    )

    # negative: deleting the already-deleted version is rejected, effect stays absent
    code, message = _client_error(
        lambda: appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id,
            ConfigurationProfileId=profile_id,
            VersionNumber=version_number,
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == not_found, f"expected {not_found!r}, got {message!r}"


def _client_error(fn):
    """Call fn(); return (code, message) of its botocore ClientError. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
