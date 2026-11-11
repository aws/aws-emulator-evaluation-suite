"""abac-configuration-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "abac-configuration-lifecycle"
GROUP = "overly-permissive"
SERVICES = ["sso-admin"]

_ACCOUNT_INSTANCE_MESSAGE = "This operation is not supported for account instances of IAM Identity Center."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """On an IAM Identity Center account instance, Create and DescribeInstanceAccessControlAttributeConfiguration
    both fail with ValidationException and the exact account-instance message: no ABAC configuration is stored."""
    sso = ctx.client("sso-admin")
    instance_arn = _get_instance_arn(ctx)

    attrs = [{"Key": "department", "Value": {"Source": ["${path:enterprise.department}"]}}]
    create_code, create_message = _error(
        lambda: sso.create_instance_access_control_attribute_configuration(
            InstanceArn=instance_arn,
            InstanceAccessControlAttributeConfiguration={"AccessControlAttributes": attrs},
        )
    )
    assert create_code == "ValidationException", (
        f"expected ValidationException from CreateInstanceAccessControlAttributeConfiguration "
        f"on an account instance, got {create_code!r} ({create_message!r})"
    )
    assert create_message == _ACCOUNT_INSTANCE_MESSAGE, create_message

    # Effect absent: no ABAC configuration was persisted despite the rejected create call. The
    # read path is gated by the identical instance-type restriction rather than a plain "not
    # found", so it must fail the same way, not merely return an empty configuration.
    describe_code, describe_message = _error(
        lambda: sso.describe_instance_access_control_attribute_configuration(InstanceArn=instance_arn)
    )
    assert describe_code == "ValidationException", (
        f"expected ValidationException from DescribeInstanceAccessControlAttributeConfiguration "
        f"on an account instance, got {describe_code!r} ({describe_message!r})"
    )
    assert describe_message == _ACCOUNT_INSTANCE_MESSAGE, describe_message


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


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because an
    over-permissive target accepting a call real AWS refuses is the strongest signal available."""
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

