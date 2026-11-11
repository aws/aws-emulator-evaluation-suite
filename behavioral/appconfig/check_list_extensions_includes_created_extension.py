"""list-extensions-includes-created-extension."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "list-extensions-includes-created-extension"
GROUP = "state-machine"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-list-extensions-includes-created-extension"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A new extension appears in ListExtensions right after creation; after its delete an
    independent read shows it gone and a read on the id fails with the not-found code.
    """
    appconfig = ctx.client("appconfig")

    ids_before = {item["Id"] for item in _paginate(appconfig, "list_extensions", "Items")}

    name = ctx.unique_name("sim2real-ext-")
    action_uri = _sns_topic_arn(ctx)
    created = appconfig.create_extension(
        Name=name,
        Description="sim2real test extension",
        Actions={"ON_DEPLOYMENT_COMPLETE": [{"Name": "noop-action", "Description": "no-op", "Uri": action_uri}]},
        Tags=_TAGS,
    )
    ext_id = created["Id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: appconfig.delete_extension(ExtensionIdentifier=ext_id)))
    assert created["VersionNumber"] == 1, f"expected initial VersionNumber 1, got {created['VersionNumber']}"
    assert created["Name"] == name, f"expected created extension named {name!r}, got {created['Name']!r}"

    ids_after = {item["Id"] for item in _paginate(appconfig, "list_extensions", "Items")}
    assert ext_id not in ids_before, "extension id unexpectedly pre-existed"
    assert ext_id in ids_after, "newly created extension missing from ListExtensions"

    matched = next(item for item in _paginate(appconfig, "list_extensions", "Items") if item["Id"] == ext_id)
    assert matched["Name"] == name, f"expected listed extension named {name!r}, got {matched['Name']!r}"
    assert matched["VersionNumber"] == 1, f"expected listed VersionNumber 1, got {matched['VersionNumber']}"

    appconfig.delete_extension(ExtensionIdentifier=ext_id)

    err = _error(lambda: appconfig.get_extension(ExtensionIdentifier=ext_id))
    assert err["Code"] == "ResourceNotFoundException", f"expected 404 after delete, got {err['Code']}"
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert err["Message"] == f"Extension could not be found for account {account}.", (
        f"unexpected message: {err['Message']!r}"
    )

    ids_after_delete = {item["Id"] for item in _paginate(appconfig, "list_extensions", "Items")}
    assert ext_id not in ids_after_delete, "deleted extension still present in ListExtensions"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _ignore_not_found(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _sns_topic_arn(ctx) -> str:
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    return f"arn:aws:sns:{ctx.region}:{account_id}:{ctx.unique_name('sim2real-topic-')}"


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
