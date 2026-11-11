"""list-applications-reflects-create-and-delete."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-applications-reflects-create-and-delete"
GROUP = "state-machine"
SERVICES = ["appconfig"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListApplications includes a newly created application and excludes it right after deletion."""
    appconfig = ctx.client("appconfig")

    name = ctx.unique_name("sim2real-app-")
    ids_before = {item["Id"] for item in _paginate(appconfig, "list_applications", "Items")}

    created = appconfig.create_application(Name=name, Description="sim2real crud check", Tags=_TAGS)
    app_id = created["Id"]
    cleaned_up = {"done": False}

    def _cleanup() -> None:
        if not cleaned_up["done"]:
            appconfig.delete_application(ApplicationId=app_id)

    ctx.on_cleanup(_cleanup)

    ids_after_create = {item["Id"] for item in _paginate(appconfig, "list_applications", "Items")}
    assert app_id not in ids_before, f"freshly minted id {app_id} already present before creation"
    assert app_id in ids_after_create, "newly created application missing from ListApplications"

    matched = next(item for item in _paginate(appconfig, "list_applications", "Items") if item["Id"] == app_id)
    assert matched["Name"] == name, f"expected Name {name!r} in ListApplications, got {matched['Name']!r}"

    appconfig.delete_application(ApplicationId=app_id)
    cleaned_up["done"] = True

    ids_after_delete = {item["Id"] for item in _paginate(appconfig, "list_applications", "Items")}
    assert app_id not in ids_after_delete, "deleted application still present in ListApplications"

    account = ctx.client("sts").get_caller_identity()["Account"]
    not_found = f"Application with Id {app_id} could not be found for account {account}."

    err = _error(lambda: appconfig.get_application(ApplicationId=app_id))
    assert err["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from GetApplication on deleted id, got {err['Code']!r}"
    )
    assert err["Message"] == not_found, f"unexpected GetApplication message: {err['Message']!r}"

    update_err = _error(lambda: appconfig.update_application(ApplicationId=app_id, Description="post-delete"))
    assert update_err["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from UpdateApplication on deleted id, got {update_err['Code']!r}"
    )
    assert update_err["Message"] == not_found, f"unexpected UpdateApplication message: {update_err['Message']!r}"


_TAGS = {
    "sim2real:managed": "true",
    "sim2real": "appconfig-list-applications-reflects-create-and-delete",
}


def _error(fn) -> dict[str, Any]:
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a ClientError on a deleted application, but the call SUCCEEDED and returned {result!r}")


def _paginate(client, op_name: str, items_key: str, **kwargs) -> list[dict[str, Any]]:
    fn = getattr(client, op_name)
    items: list[dict[str, Any]] = []
    next_token = None
    while True:
        params = dict(kwargs)
        if next_token:
            params["NextToken"] = next_token
        resp = fn(**params)
        items.extend(resp.get(items_key, []))
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
