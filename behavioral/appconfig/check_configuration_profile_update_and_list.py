"""configuration-profile-update-and-list."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "configuration-profile-update-and-list"
GROUP = "configuration-profile"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-configuration-profile-update-and-list"}


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateConfigurationProfile mutates persisted fields; List/Delete reflect membership changes."""
    appconfig = ctx.client("appconfig")
    app_id = _create_application(ctx, appconfig)

    created = appconfig.create_configuration_profile(
        ApplicationId=app_id,
        Name="cp-v1",
        Description="first",
        LocationUri="hosted",
        Type="AWS.Freeform",
        Tags=_TAGS,
    )
    cp_id = created["Id"]
    assert created["Name"] == "cp-v1", f"expected Name='cp-v1' on create response, got {created['Name']!r}"
    ctx.on_cleanup(lambda: _safe_delete_profile(appconfig, app_id, cp_id))

    got = appconfig.get_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=cp_id)
    assert got["Name"] == "cp-v1", f"expected Name='cp-v1', got {got['Name']!r}"
    assert got["Description"] == "first", f"expected Description='first', got {got['Description']!r}"
    assert got["LocationUri"] == "hosted", f"expected LocationUri='hosted', got {got['LocationUri']!r}"

    updated = appconfig.update_configuration_profile(
        ApplicationId=app_id,
        ConfigurationProfileId=cp_id,
        Name="cp-v2",
        Description="second",
    )
    assert updated["Name"] == "cp-v2", f"expected Name='cp-v2' on update response, got {updated['Name']!r}"
    assert updated["Description"] == "second", (
        f"expected Description='second' on update response, got {updated['Description']!r}"
    )

    got2 = appconfig.get_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=cp_id)
    assert got2["Name"] == "cp-v2", f"expected persisted Name='cp-v2', got {got2['Name']!r}"
    assert got2["Description"] == "second", f"expected persisted Description='second', got {got2['Description']!r}"

    items = _list_all_profiles(appconfig, app_id)
    match = next((i for i in items if i["Id"] == cp_id), None)
    assert match is not None, f"configuration profile {cp_id} missing from ListConfigurationProfiles"
    assert match["Name"] == "cp-v2", f"expected listed Name='cp-v2', got {match['Name']!r}"

    appconfig.delete_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=cp_id)

    items_after = _list_all_profiles(appconfig, app_id)
    assert all(i["Id"] != cp_id for i in items_after), "deleted profile still listed"

    account = ctx.client("sts").get_caller_identity()["Account"]
    not_found = (
        f"Configuration Profile with Application Id {app_id} and Configuration Profile Id "
        f"{cp_id} could not be found for account {account}."
    )
    code, message = _error(
        lambda: appconfig.get_configuration_profile(ApplicationId=app_id, ConfigurationProfileId=cp_id)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == not_found, f"expected message {not_found!r}, got {message!r}"

    # A mutation on the dead id must also fail, not just the read.
    update_code, update_message = _error(
        lambda: appconfig.update_configuration_profile(
            ApplicationId=app_id, ConfigurationProfileId=cp_id, Description="post-delete"
        )
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected UpdateConfigurationProfile on deleted id to fail with ResourceNotFoundException, "
        f"got {update_code}"
    )
    assert update_message == not_found, f"expected message {not_found!r}, got {update_message!r}"


def _error(fn):
    """Call fn(); return its botocore (error code, error message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to fail, but it SUCCEEDED and returned {result!r}")


def _create_application(ctx, appconfig):
    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: _safe_delete_application(appconfig, app_id))
    return app_id


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


def _list_all_profiles(appconfig, app_id):
    items = []
    kwargs = {"ApplicationId": app_id}
    while True:
        resp = appconfig.list_configuration_profiles(**kwargs)
        items.extend(resp.get("Items", []))
        token = resp.get("NextToken")
        if not token:
            break
        kwargs = {"ApplicationId": app_id, "NextToken": token}
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
