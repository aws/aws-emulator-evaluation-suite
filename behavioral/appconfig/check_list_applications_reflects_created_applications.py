"""list-applications-reflects-created-applications."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-applications-reflects-created-applications"
GROUP = "data-plane"
SERVICES = ["appconfig"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A new application appears in ListApplications and is gone from it right after
    DeleteApplication, and the deleted id is unusable, not merely unlisted.
    """
    appconfig = ctx.client("appconfig")
    name = ctx.unique_name("sim2real-appcfg-list-app-")
    app_id = appconfig.create_application(
        Name=name, Tags={"sim2real-check": "list-applications-reflects-created-applications"}
    )["Id"]
    ctx.on_cleanup(lambda: _safe_delete_application(appconfig, app_id))

    ids_after_create = _list_all_application_ids(appconfig)
    assert app_id in ids_after_create, f"{app_id} missing from ListApplications after create"

    appconfig.delete_application(ApplicationId=app_id)

    ids_after_delete = _list_all_application_ids(appconfig)
    assert app_id not in ids_after_delete, f"{app_id} still present in ListApplications after delete"

    err = _error(lambda: appconfig.get_application(ApplicationId=app_id))
    assert err["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err['Code']}"
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert err["Message"] == f"Application with Id {app_id} could not be found for account {account}.", (
        f"unexpected message: {err['Message']!r}"
    )


def _error(fn) -> dict:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a ClientError on a deleted application, but the call succeeded and returned {result!r}")


def _safe_delete_application(appconfig, app_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        appconfig.delete_application(ApplicationId=app_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _list_all_application_ids(appconfig) -> set[str]:
    ids: set[str] = set()
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = appconfig.list_applications(**kwargs)
        ids.update(item["Id"] for item in resp["Items"])
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return ids


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
