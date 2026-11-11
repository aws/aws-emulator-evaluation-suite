"""application-tag-quota-exceeded-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "application-tag-quota-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["sso-admin"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """An application takes 50 tags, but one more TagResource fails with ServiceQuotaExceededException and the exact
    50-tag message, and the tag set stays at 50 without the extra key."""
    sso = ctx.client("sso-admin")
    instance_arn = _get_instance_arn(ctx)
    provider_arn = _pick_oauth_provider_arn(ctx)
    app_arn = sso.create_application(
        InstanceArn=instance_arn,
        ApplicationProviderArn=provider_arn,
        Name=ctx.unique_name("sim2real-behav-app-"),
    )["ApplicationArn"]
    ctx.on_cleanup(lambda: sso.delete_application(ApplicationArn=app_arn))

    # Positive control: exactly 50 tags (the documented max TagList length for this resource
    # type) in one call succeeds.
    max_tags = [{"Key": f"k{i}", "Value": f"v{i}"} for i in range(50)]
    sso.tag_resource(ResourceArn=app_arn, Tags=max_tags)

    tags_after_max = sso.list_tags_for_resource(ResourceArn=app_arn)["Tags"]
    assert len(tags_after_max) == 50, f"expected 50 tags at the quota boundary, got {len(tags_after_max)}"

    # One more tag (a distinct key, valid on its own) pushes the resource-level total to 51.
    code, message = _error(
        lambda: sso.tag_resource(ResourceArn=app_arn, Tags=[{"Key": "one-too-many", "Value": "x"}])
    )
    assert code == "ServiceQuotaExceededException", (
        f"expected ServiceQuotaExceededException for the 51st tag, got {code!r}"
    )
    assert message == "50 user tags are allowed for a resource at maximum, The resultant tag set must not have more than 50 user tags.", message

    tags_after_rejected = sso.list_tags_for_resource(ResourceArn=app_arn)["Tags"]
    assert len(tags_after_rejected) == 50, (
        f"expected the rejected call to leave the tag count at 50, got {len(tags_after_rejected)}"
    )
    assert not any(t["Key"] == "one-too-many" for t in tags_after_rejected), (
        "the rejected 'one-too-many' tag was persisted despite ServiceQuotaExceededException"
    )


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
    accepts a call AWS refuses fails loudly rather than reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

