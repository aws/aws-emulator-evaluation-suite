"""application-not-found-describe-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "application-not-found-describe-rejected"
GROUP = "overly-permissive"
SERVICES = ["sso-admin"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """DescribeApplication on an unknown ApplicationArn fails with ResourceNotFoundException "No resource found for
    application arn: <arn>", answers for a real application, and fails the same way once that application is
    deleted."""
    sso = ctx.client("sso-admin")
    instance_arn = _get_instance_arn(ctx)
    provider_arn = _pick_oauth_provider_arn(ctx)
    instance_id = instance_arn.rsplit("/", 1)[-1]
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    real_arn = sso.create_application(
        InstanceArn=instance_arn,
        ApplicationProviderArn=provider_arn,
        Name=ctx.unique_name("sim2real-behav-app-"),
    )["ApplicationArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: sso.delete_application(ApplicationArn=real_arn)))

    bogus_arn = f"arn:aws:sso::{account_id}:application/{instance_id}/apl-0123456789abcdef"
    code, message = _error(lambda: sso.describe_application(ApplicationArn=bogus_arn))
    assert code == "ResourceNotFoundException", code
    assert message == f"No resource found for application arn: {bogus_arn}", message

    # Positive control: the real application still describes cleanly.
    described = sso.describe_application(ApplicationArn=real_arn)
    assert described["ApplicationArn"] == real_arn, described

    sso.delete_application(ApplicationArn=real_arn)
    code_after, msg_after = _error(lambda: sso.describe_application(ApplicationArn=real_arn))
    assert code_after == "ResourceNotFoundException", code_after
    assert msg_after == f"No resource found for application arn: {real_arn}", msg_after


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


def _ignore_not_found(fn):
    """Teardown for a resource the check may already have deleted itself."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

