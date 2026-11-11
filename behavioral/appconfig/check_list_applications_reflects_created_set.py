"""list-applications-reflects-created-set."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-applications-reflects-created-set"
GROUP = "data-plane"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-list-applications"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListApplications includes both just-created applications and no never-created id; deleting
    one removes only it from the listing, and GetApplication on it then fails with
    ResourceNotFoundException."""
    ctx.client("appconfig")
    app_id_1 = _create_application(ctx)
    app_id_2 = _create_application(ctx)

    all_ids = {item["Id"] for item in _list_all_applications(ctx)}
    assert app_id_1 in all_ids, f"{app_id_1} missing from ListApplications"
    assert app_id_2 in all_ids, f"{app_id_2} missing from ListApplications"

    # A well-formed id that was never created; a static listing would not be caught otherwise.
    never_created = "zzzzzz9"
    assert never_created not in all_ids, (
        f"never-created id {never_created} present in ListApplications: {all_ids}"
    )

    appconfig = ctx.client("appconfig")
    appconfig.delete_application(ApplicationId=app_id_1)

    ids_after_delete = {item["Id"] for item in _list_all_applications(ctx)}
    assert app_id_1 not in ids_after_delete, (
        f"deleted application {app_id_1} still present in ListApplications"
    )
    assert app_id_2 in ids_after_delete, (
        f"unrelated application {app_id_2} disappeared after deleting {app_id_1}"
    )

    err = _error(ctx, app_id_1)
    assert err["Code"] == "ResourceNotFoundException", (
        f"GetApplication({app_id_1}) after delete returned {err['Code']!r}, expected ResourceNotFoundException"
    )
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert err["Message"] == f"Application with Id {app_id_1} could not be found for account {account}.", (
        f"unexpected message: {err['Message']!r}"
    )


def _error(ctx, app_id: str) -> dict:
    from botocore.exceptions import ClientError

    appconfig = ctx.client("appconfig")
    try:
        appconfig.get_application(ApplicationId=app_id)
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"GetApplication({app_id}) unexpectedly succeeded after delete")


def _create_application(ctx) -> str:
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(
        Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(lambda: _safe_delete_application(appconfig, app_id))
    return app_id


def _safe_delete_application(appconfig, app_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        appconfig.delete_application(ApplicationId=app_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _list_all_applications(ctx) -> list[dict]:
    appconfig = ctx.client("appconfig")
    items: list[dict] = []
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = appconfig.list_applications(**kwargs)
        items.extend(resp.get("Items", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
