"""extension-association-update-and-list-reflects-latest-parameters."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "extension-association-update-and-list-reflects-latest-parameters"
GROUP = "state-machine"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-extension-association-update-list"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Updating an association's parameters is visible via GetExtensionAssociation; ListExtensionAssociations
    keeps tracking the same association by id/arns throughout."""
    appconfig = ctx.client("appconfig")

    ext_name = ctx.unique_name("sim2real-ext-")
    action_uri = _sns_topic_arn(ctx)
    ext = appconfig.create_extension(
        Name=ext_name,
        Actions={"ON_DEPLOYMENT_COMPLETE": [{"Name": "noop-action", "Uri": action_uri}]},
        Parameters={"greeting": {"Required": True, "Description": "a greeting"}},
        Tags=_TAGS,
    )
    ext_id = ext["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_extension(ExtensionIdentifier=ext_id))

    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-app-"), Tags=_TAGS)["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    app_arn = _app_arn(ctx, app_id)

    assoc = appconfig.create_extension_association(
        ExtensionIdentifier=ext_id, ResourceIdentifier=app_arn, Parameters={"greeting": "hello"}, Tags=_TAGS
    )
    assoc_id = assoc["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_extension_association(ExtensionAssociationId=assoc_id))
    assert assoc["Parameters"] == {"greeting": "hello"}, (
        f"CreateExtensionAssociation echoed Parameters={assoc['Parameters']!r}, expected {{'greeting': 'hello'}}"
    )

    got_before = appconfig.get_extension_association(ExtensionAssociationId=assoc_id)
    assert got_before["Parameters"] == {"greeting": "hello"}, (
        f"GetExtensionAssociation before update returned Parameters={got_before['Parameters']!r}, "
        f"expected {{'greeting': 'hello'}}"
    )

    listed_before = _paginate(appconfig, "list_extension_associations", "Items")
    matched_before = next(item for item in listed_before if item["Id"] == assoc_id)
    assert matched_before["ExtensionArn"] == assoc["ExtensionArn"], (
        f"ListExtensionAssociations reported ExtensionArn={matched_before['ExtensionArn']!r} before update, "
        f"expected {assoc['ExtensionArn']!r}"
    )
    assert matched_before["ResourceArn"] == app_arn, (
        f"ListExtensionAssociations reported ResourceArn={matched_before['ResourceArn']!r} before update, "
        f"expected {app_arn!r}"
    )

    updated = appconfig.update_extension_association(
        ExtensionAssociationId=assoc_id, Parameters={"greeting": "goodbye"}
    )
    assert updated["Parameters"] == {"greeting": "goodbye"}, (
        f"UpdateExtensionAssociation echoed Parameters={updated['Parameters']!r}, expected {{'greeting': 'goodbye'}}"
    )

    got_after = appconfig.get_extension_association(ExtensionAssociationId=assoc_id)
    assert got_after["Parameters"] == {"greeting": "goodbye"}, (
        f"GetExtensionAssociation after update returned Parameters={got_after['Parameters']!r}, "
        f"expected the persisted {{'greeting': 'goodbye'}}"
    )

    listed_after = _paginate(appconfig, "list_extension_associations", "Items")
    matched_after = next(item for item in listed_after if item["Id"] == assoc_id)
    assert matched_after["ExtensionArn"] == assoc["ExtensionArn"], (
        f"ListExtensionAssociations reported ExtensionArn={matched_after['ExtensionArn']!r} after update, "
        f"expected {assoc['ExtensionArn']!r} (unchanged by the parameter update)"
    )
    assert matched_after["ResourceArn"] == app_arn, (
        f"ListExtensionAssociations reported ResourceArn={matched_after['ResourceArn']!r} after update, "
        f"expected {app_arn!r} (unchanged by the parameter update)"
    )


def _app_arn(ctx, app_id: str) -> str:
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    return f"arn:aws:appconfig:{ctx.region}:{account_id}:application/{app_id}"


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
