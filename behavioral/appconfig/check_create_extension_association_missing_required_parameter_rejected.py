"""create-extension-association-missing-required-parameter-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-extension-association-missing-required-parameter-rejected"
GROUP = "overly-permissive"
SERVICES = ["appconfig"]

_TAGS = {"sim2real:managed": "true", "sim2real": "appconfig-create-extension-association-missing-required-parameter"}
_SNS_TAGS = [{"Key": "sim2real", "Value": "appconfig-create-extension-association-missing-required-parameter"}, {"Key": "sim2real:managed", "Value": "true"}]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateExtensionAssociation omitting a Required extension parameter fails with
    BadRequestException and creates nothing; supplying the parameter succeeds."""
    appconfig = ctx.client("appconfig")
    sns = ctx.client("sns")

    topic_arn = sns.create_topic(
        Name=ctx.unique_name("sim2real-behav-topic-"), Tags=_SNS_TAGS
    )["TopicArn"]
    ctx.on_cleanup(lambda: sns.delete_topic(TopicArn=topic_arn))

    ext_name = ctx.unique_name("sim2real-behav-ext-")
    ext = appconfig.create_extension(
        Name=ext_name,
        Actions={"ON_DEPLOYMENT_COMPLETE": [{"Name": "notify", "Uri": topic_arn}]},
        Parameters={"MyRequiredParam": {"Required": True}},
        Tags=_TAGS,
    )
    ext_id = ext["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_extension(ExtensionIdentifier=ext_id))

    app_id = _create_application(ctx)
    app_arn = _application_arn(ctx, app_id)

    code, message = _error(
        lambda: appconfig.create_extension_association(
            ExtensionIdentifier=ext_id, ResourceIdentifier=app_arn
        )
    )
    assert code == "BadRequestException", (
        f"CreateExtensionAssociation omitting the required parameter MyRequiredParam must be "
        f"refused with BadRequestException, got {code!r}"
    )
    expected = (
        f"Extension {ext_name} version 1 has required parameters, but no parameters have been "
        "supplied"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # the rejected call created no association at all
    associations = _list_all_extension_associations(ctx, resource_identifier=app_arn)
    assert associations == [], f"association leaked despite missing required parameter: {associations}"

    # positive control: supplying the required parameter succeeds
    association = appconfig.create_extension_association(
        ExtensionIdentifier=ext_id,
        ResourceIdentifier=app_arn,
        Parameters={"MyRequiredParam": "value"},
        Tags=_TAGS,
    )
    ctx.on_cleanup(
        lambda: appconfig.delete_extension_association(
            ExtensionAssociationId=association["Id"]
        )
    )
    associations_after = _list_all_extension_associations(ctx, resource_identifier=app_arn)
    assert association["Id"] in {a["Id"] for a in associations_after}, (
        f"the association created by the positive control ({association['Id']!r}) must appear "
        f"in ListExtensionAssociations, got {[a['Id'] for a in associations_after]!r}"
    )


def _error(fn):
    """Call fn() and return its (error code, error message); an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _application_arn(ctx, app_id: str) -> str:
    return f"arn:aws:appconfig:{ctx.region}:{_account_id(ctx)}:application/{app_id}"


def _create_application(ctx) -> str:
    appconfig = ctx.client("appconfig")
    app_id = appconfig.create_application(
        Name=ctx.unique_name("sim2real-behav-app-"), Tags=_TAGS
    )["Id"]
    ctx.on_cleanup(lambda: appconfig.delete_application(ApplicationId=app_id))
    return app_id


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
