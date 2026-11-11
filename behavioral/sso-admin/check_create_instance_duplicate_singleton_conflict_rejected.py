"""create-instance-duplicate-singleton-conflict-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-instance-duplicate-singleton-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["sso-admin"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """CreateInstance while an instance exists fails with ServiceQuotaExceededException and the exact one-instance
    message, and ListInstances still shows the one ACTIVE instance at the same InstanceArn."""
    sso = ctx.client("sso-admin")
    instance_arn = _get_instance_arn(ctx)

    before = sso.list_instances()["Instances"]
    assert len(before) == 1, f"expected exactly 1 instance before the duplicate attempt, got {before!r}"
    assert before[0]["InstanceArn"] == instance_arn, (
        f"expected the sole instance to be {instance_arn!r}, got {before[0]['InstanceArn']!r}"
    )

    code, message = _error_code(lambda: sso.create_instance(Name=ctx.unique_name("sim2real-behav-instance-dup-")))
    assert code == "ServiceQuotaExceededException", f"expected ServiceQuotaExceededException, got {code!r}"
    assert message == f"You have exceeded IAM Identity Center quotas. Cannot create more than 1 instance for {ctx.account}. Please refer to https://docs.aws.amazon.com/singlesignon/latest/userguide/limits.html", (
        f"expected the exact ServiceQuotaExceededException message AWS returns, got {message!r}"
    )

    # Effect absent: still exactly one instance, same ARN, same status.
    after = sso.list_instances()["Instances"]
    assert len(after) == 1, f"expected exactly 1 instance after the rejected duplicate, got {after!r}"
    assert after[0]["InstanceArn"] == instance_arn, (
        f"expected the original instance {instance_arn!r} to remain, got {after[0]['InstanceArn']!r}"
    )
    status = sso.describe_instance(InstanceArn=instance_arn)["Status"]
    assert status == "ACTIVE", f"expected the original instance to remain ACTIVE, got {status!r}"


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


def _error_code(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

