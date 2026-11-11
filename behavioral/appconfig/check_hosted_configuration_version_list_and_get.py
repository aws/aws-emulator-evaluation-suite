"""hosted-configuration-version-list-and-get."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "hosted-configuration-version-list-and-get"
GROUP = "hosted-configuration-version"
SERVICES = ["appconfig"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListHostedConfigurationVersions reflects created versions (newest first) and
    DeleteHostedConfigurationVersion removes entries from both the list and Get."""
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-app-"))["Id"]
    ctx.on_cleanup(lambda: _safe_delete_application(appconfig, app_id))

    cp_id = appconfig.create_configuration_profile(
        ApplicationId=app_id, Name="cp-hcv", LocationUri="hosted", Type="AWS.Freeform"
    )["Id"]
    ctx.on_cleanup(lambda: _safe_delete_profile(appconfig, app_id, cp_id))

    version_numbers = []
    for i in (1, 2, 3):
        resp = appconfig.create_hosted_configuration_version(
            ApplicationId=app_id,
            ConfigurationProfileId=cp_id,
            Content=f"version-{i}".encode("utf-8"),
            ContentType="text/plain",
        )
        version_numbers.append(resp["VersionNumber"])
    assert version_numbers == sorted(version_numbers), "version numbers should be monotonically increasing"
    v1, v2, v3 = version_numbers
    for v in version_numbers:
        ctx.on_cleanup(lambda v=v: _safe_delete_version(appconfig, app_id, cp_id, v))

    items = _list_all_versions(appconfig, app_id, cp_id)
    listed_numbers = [i["VersionNumber"] for i in items]
    assert set(listed_numbers) == {v1, v2, v3}, (
        f"expected exactly the three created versions {{{v1}, {v2}, {v3}}}, got {listed_numbers}"
    )
    # AppConfig returns hosted configuration versions newest-first.
    assert listed_numbers == sorted(listed_numbers, reverse=True), (
        f"expected descending order, got {listed_numbers}"
    )

    got_v2 = appconfig.get_hosted_configuration_version(
        ApplicationId=app_id, ConfigurationProfileId=cp_id, VersionNumber=v2
    )
    content_v2 = got_v2["Content"].read()
    assert content_v2 == b"version-2", f"expected b'version-2', got {content_v2!r}"
    assert got_v2["ContentType"] == "text/plain", (
        f"expected ContentType text/plain, got {got_v2['ContentType']!r}"
    )

    appconfig.delete_hosted_configuration_version(
        ApplicationId=app_id, ConfigurationProfileId=cp_id, VersionNumber=v2
    )

    items_after = _list_all_versions(appconfig, app_id, cp_id)
    remaining = {i["VersionNumber"] for i in items_after}
    assert v2 not in remaining, "deleted version still present in ListHostedConfigurationVersions"
    assert v1 in remaining and v3 in remaining, (
        f"expected undeleted versions {{{v1}, {v3}}} to remain, got {remaining}"
    )

    code, code_msg = _error(
        lambda: appconfig.get_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=cp_id, VersionNumber=v2
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert code_msg == (
        f"Hosted Configuration Version with Application Id {app_id}, Configuration Profile Id "
        f"{cp_id}, and Version {v2} could not be found for account {account}"
    ), f"unexpected message: {code_msg!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe_delete_application(appconfig, app_id):
    try:
        appconfig.delete_application(ApplicationId=app_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_profile(appconfig, app_id, cp_id):
    try:
        appconfig.delete_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=cp_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_version(appconfig, app_id, cp_id, version_number):
    try:
        appconfig.delete_hosted_configuration_version(
            ApplicationId=app_id, ConfigurationProfileId=cp_id, VersionNumber=version_number
        )
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _list_all_versions(appconfig, app_id, cp_id):
    items = []
    kwargs = {"ApplicationId": app_id, "ConfigurationProfileId": cp_id}
    while True:
        resp = appconfig.list_hosted_configuration_versions(**kwargs)
        items.extend(resp.get("Items", []))
        token = resp.get("NextToken")
        if not token:
            break
        kwargs = {"ApplicationId": app_id, "ConfigurationProfileId": cp_id, "NextToken": token}
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
