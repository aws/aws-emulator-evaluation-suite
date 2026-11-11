"""application-lifecycle-list-and-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "application-lifecycle-list-and-delete"
GROUP = "application"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-application-lifecycle-list-and-delete"}


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Create/Get/Update transitions are reflected in ListApplications; 404 after DeleteApplication."""
    appconfig = ctx.client("appconfig")
    account = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-app-")

    created = appconfig.create_application(Name=name, Description="v1", Tags=_TAGS)
    app_id = created["Id"]
    assert created["Name"] == name, f"expected Name={name!r}, got {created['Name']!r}"
    assert created["Description"] == "v1", f"expected Description='v1', got {created['Description']!r}"
    ctx.on_cleanup(lambda: _safe_delete_application(appconfig, app_id))

    got = appconfig.get_application(ApplicationId=app_id)
    assert got["Id"] == app_id, f"expected Id={app_id!r}, got {got['Id']!r}"
    assert got["Description"] == "v1", f"expected Description='v1', got {got['Description']!r}"

    updated = appconfig.update_application(ApplicationId=app_id, Description="v2")
    assert updated["Description"] == "v2", f"expected Description='v2', got {updated['Description']!r}"
    assert updated["Name"] == name, f"expected Name unchanged at {name!r}, got {updated['Name']!r}"

    got2 = appconfig.get_application(ApplicationId=app_id)
    assert got2["Description"] == "v2", f"expected Description='v2', got {got2['Description']!r}"

    items = _list_all_applications(appconfig)
    match = next((i for i in items if i["Id"] == app_id), None)
    assert match is not None, "application not found in ListApplications after update"
    assert match["Description"] == "v2", f"expected Description='v2' in listing, got {match['Description']!r}"

    appconfig.delete_application(ApplicationId=app_id)

    not_found = f"Application with Id {app_id} could not be found for account {account}."
    code, message = _error(lambda: appconfig.get_application(ApplicationId=app_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == not_found, f"expected message {not_found!r}, got {message!r}"

    items_after = _list_all_applications(appconfig)
    assert all(i["Id"] != app_id for i in items_after), "deleted application still present in ListApplications"

    mutate_code, mutate_message = _error(
        lambda: appconfig.update_application(ApplicationId=app_id, Description="v3")
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"expected a mutation on the deleted application id to also be rejected with "
        f"ResourceNotFoundException, got {mutate_code}"
    )
    assert mutate_message == not_found, f"expected message {not_found!r}, got {mutate_message!r}"


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of its ClientError. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to fail, but it SUCCEEDED and returned {result!r}")


def _list_all_applications(appconfig):
    items = []
    kwargs = {}
    while True:
        resp = appconfig.list_applications(**kwargs)
        items.extend(resp.get("Items", []))
        token = resp.get("NextToken")
        if not token:
            break
        kwargs = {"NextToken": token}
    return items


def _safe_delete_application(appconfig, app_id):
    try:
        appconfig.delete_application(ApplicationId=app_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
