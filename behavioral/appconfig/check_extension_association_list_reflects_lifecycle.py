"""extension-association-list-reflects-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "extension-association-list-reflects-lifecycle"
GROUP = "data-plane"
SERVICES = ["appconfig"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListExtensionAssociations shows an association right after create and omits it right after
    delete; Get/UpdateExtensionAssociation on the deleted id then fail with
    ResourceNotFoundException, while the extension itself stays listed."""
    appconfig = ctx.client("appconfig")
    sns = ctx.client("sns")

    app_id = _create_application(ctx)
    app_arn = _application_arn(ctx, app_id)

    topic_arn = sns.create_topic(Name=ctx.unique_name("sim2real-behav-topic-"))["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    ext_name = ctx.unique_name("sim2real-behav-ext-")
    actions = {"ON_DEPLOYMENT_COMPLETE": [{"Name": "notify", "Uri": topic_arn}]}
    ext = appconfig.create_extension(Name=ext_name, Actions=actions)
    ext_id = ext["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_extension(ExtensionIdentifier=ext_id))

    assert ext_id in {e["Id"] for e in _list_all_extensions(ctx)}

    association = appconfig.create_extension_association(
        ExtensionIdentifier=ext_id, ResourceIdentifier=app_arn
    )
    assoc_id = association["Id"]

    associations_after_create = _list_all_extension_associations(ctx, resource_identifier=app_arn)
    assert assoc_id in {a["Id"] for a in associations_after_create}, (
        "association missing from ListExtensionAssociations right after creation"
    )

    appconfig.delete_extension_association(ExtensionAssociationId=assoc_id)

    associations_after_delete = _list_all_extension_associations(ctx, resource_identifier=app_arn)
    assert assoc_id not in {a["Id"] for a in associations_after_delete}, (
        "association still present in ListExtensionAssociations after deletion"
    )

    not_found = f"ExtensionAssociation could not be found for account {_account_id(ctx)}."
    get_err = _client_error(lambda: appconfig.get_extension_association(ExtensionAssociationId=assoc_id))
    assert get_err["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from GetExtensionAssociation after delete, got {get_err['Code']}"
    )
    assert get_err["Message"] == not_found, f"expected message {not_found!r}, got {get_err['Message']!r}"

    update_err = _client_error(
        lambda: appconfig.update_extension_association(ExtensionAssociationId=assoc_id, Parameters={})
    )
    assert update_err["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from UpdateExtensionAssociation on a deleted id, got {update_err['Code']}"
    )
    assert update_err["Message"] == not_found, f"expected message {not_found!r}, got {update_err['Message']!r}"

    # the extension itself is untouched by deleting one of its associations
    assert ext_id in {e["Id"] for e in _list_all_extensions(ctx)}


def _client_error(fn) -> dict:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _application_arn(ctx, app_id: str) -> str:
    return f"arn:aws:appconfig:{ctx.region}:{_account_id(ctx)}:application/{app_id}"


def _create_application(ctx) -> str:
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(Name=ctx.unique_name("sim2real-behav-app-"))["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    return app_id


def _list_all_extensions(ctx) -> list[dict]:
    appconfig = ctx.client("appconfig")
    items: list[dict] = []
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = appconfig.list_extensions(**kwargs)
        items.extend(resp.get("Items", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return items


def _list_all_extension_associations(ctx, *, resource_identifier: str) -> list[dict]:
    appconfig = ctx.client("appconfig")
    items: list[dict] = []
    next_token = None
    while True:
        kwargs = {"ResourceIdentifier": resource_identifier}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = appconfig.list_extension_associations(**kwargs)
        items.extend(resp.get("Items", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
