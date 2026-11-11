"""list-extension-associations-reflects-created-associations."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-extension-associations-reflects-created-associations"
GROUP = "data-plane"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-list-extension-associations"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListExtensionAssociations lists a new association immediately and omits it immediately after
    DeleteExtensionAssociation; GetExtensionAssociation on the deleted id then fails with
    ResourceNotFoundException."""
    appconfig = ctx.client("appconfig")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    ext = appconfig.create_extension(
        Name=ctx.unique_name("sim2real-appcfg-ext-"),
        Actions={
            "ON_DEPLOYMENT_COMPLETE": [
                {"Name": "notify", "Uri": f"arn:aws:sns:{ctx.region}:{account_id}:sim2real-appcfg-topic"}
            ]
        },
        Tags=_TAGS,
    )
    ext_id = ext["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_extension(ExtensionIdentifier=ext_id))

    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-appcfg-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    app_arn = f"arn:aws:appconfig:{ctx.region}:{account_id}:application/{app_id}"

    assoc = appconfig.create_extension_association(
        ExtensionIdentifier=ext_id, ResourceIdentifier=app_arn, Tags=_TAGS
    )
    assoc_id = assoc["Id"]
    ctx.on_cleanup(lambda: _safe_delete_association(appconfig, assoc_id))

    ids_after_create = _list_all_association_ids(appconfig)
    assert assoc_id in ids_after_create, (
        f"expected {assoc_id} in ListExtensionAssociations right after CreateExtensionAssociation, "
        f"got {ids_after_create}"
    )

    appconfig.delete_extension_association(ExtensionAssociationId=assoc_id)

    ids_after_delete = _list_all_association_ids(appconfig)
    assert assoc_id not in ids_after_delete, (
        f"expected {assoc_id} absent from ListExtensionAssociations after DeleteExtensionAssociation, "
        f"still present in {ids_after_delete}"
    )

    err = _error(lambda: appconfig.get_extension_association(ExtensionAssociationId=assoc_id))
    assert err["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from GetExtensionAssociation on the deleted id, got {err['Code']}"
    )
    assert err["Message"] == f"ExtensionAssociation could not be found for account {account_id}.", (
        f"unexpected message: {err['Message']!r}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe_delete_association(appconfig, assoc_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        appconfig.delete_extension_association(ExtensionAssociationId=assoc_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _list_all_association_ids(appconfig) -> set[str]:
    ids: set[str] = set()
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = appconfig.list_extension_associations(**kwargs)
        ids.update(item["Id"] for item in resp["Items"])
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return ids


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
