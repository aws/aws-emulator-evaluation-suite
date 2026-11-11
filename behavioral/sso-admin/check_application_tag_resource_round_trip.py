"""application-tag-resource-round-trip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "application-tag-resource-round-trip"
GROUP = "state"
SERVICES = ["sso-admin"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """TagResource / ListTagsForResource / UntagResource round-trip on an application ARN, and
    DeleteApplication removes the tagged resource entirely -- a subsequent ListTagsForResource and
    a subsequent TagResource on the dead ARN both 404."""
    sso = ctx.client("sso-admin")
    instance_arn = _get_instance_arn(ctx)
    provider_arn = _pick_oauth_provider_arn(ctx)
    app_arn = sso.create_application(
        InstanceArn=instance_arn,
        ApplicationProviderArn=provider_arn,
        Name=ctx.unique_name("sim2real-behav-app-"),
    )["ApplicationArn"]
    ctx.on_cleanup(lambda: _safe(lambda: sso.delete_application(ApplicationArn=app_arn)))

    sso.tag_resource(
        ResourceArn=app_arn,
        Tags=[{"Key": "team", "Value": "platform"}, {"Key": "env", "Value": "test"}],
    )

    tags_after_tag = {t["Key"]: t["Value"] for t in sso.list_tags_for_resource(ResourceArn=app_arn)["Tags"]}
    assert tags_after_tag == {"team": "platform", "env": "test"}, (
        f"expected both tags right after TagResource, got {tags_after_tag}"
    )

    sso.untag_resource(ResourceArn=app_arn, TagKeys=["env"])

    tags_after_untag = {t["Key"]: t["Value"] for t in sso.list_tags_for_resource(ResourceArn=app_arn)["Tags"]}
    assert tags_after_untag == {"team": "platform"}, (
        f"expected only 'team' to survive UntagResource(['env']), got {tags_after_untag}"
    )

    sso.delete_application(ApplicationArn=app_arn)

    code, message = _error(lambda: sso.list_tags_for_resource(ResourceArn=app_arn))
    assert code == "ResourceNotFoundException", (
        f"expected ListTagsForResource on a deleted application to 404, got {code!r}"
    )
    assert message == f"No resource found for application arn: {app_arn}", message

    code, message = _error(lambda: sso.tag_resource(ResourceArn=app_arn, Tags=[{"Key": "k", "Value": "v"}]))
    assert code == "ResourceNotFoundException", (
        f"expected TagResource on a deleted application to 404, got {code!r}"
    )
    assert message == f"Could not find Application with id {app_arn}.", message


def _get_instance_arn(ctx):
    import time

    sso = ctx.client("sso-admin")
    instances = sso.list_instances().get("Instances", [])
    if instances:
        instance_arn = instances[0]["InstanceArn"]
    else:
        instance_arn = sso.create_instance()["InstanceArn"]
    deadline = time.time() + 120
    status = None
    while time.time() < deadline:
        status = sso.describe_instance(InstanceArn=instance_arn)["Status"]
        if status == "ACTIVE":
            return instance_arn
        if status in ("CREATE_FAILED", "DELETE_IN_PROGRESS"):
            raise RuntimeError(f"IAM Identity Center instance in unexpected state: {status}")
        time.sleep(3)
    raise RuntimeError(f"IAM Identity Center instance did not become ACTIVE in time (last status: {status})")


def _pick_oauth_provider_arn(ctx):

    sso = ctx.client("sso-admin")
    providers = {p["ApplicationProviderArn"] for p in sso.list_application_providers().get("ApplicationProviders", [])}
    custom_arn = "arn:aws:sso::aws:applicationProvider/custom"
    if custom_arn not in providers:
        raise AssertionError("the generic customer-managed OAuth2 application provider is not available in this partition")
    return custom_arn


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises, so a target that
    accepts a call AWS refuses fails loudly instead of reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

