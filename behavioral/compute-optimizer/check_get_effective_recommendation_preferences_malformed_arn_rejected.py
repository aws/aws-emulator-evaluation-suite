"""get-effective-recommendation-preferences-malformed-arn-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-effective-recommendation-preferences-malformed-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["compute-optimizer"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx) -> None:
    """GetEffectiveRecommendationPreferences rejects a syntactically malformed
    resourceArn with InvalidParameterValueException, while the identical operation
    against a real, existing EC2 instance ARN succeeds.
    """
    co = ctx.client("compute-optimizer")
    _ensure_opted_in(co)

    code, message = _error(lambda: co.get_effective_recommendation_preferences(resourceArn="not-an-arn"))
    assert code == "InvalidParameterValueException", f"expected InvalidParameterValueException, got {code}"
    expected = "Invalid Amazon Resource Name (ARN) specified. Please check the resource name and try again."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # positive control: a real, well-formed resourceArn succeeds on the same operation,
    # and the effective value tracks a resource-level preference we set ourselves --
    # not merely a member of the full two-value enum, which no target could fail.
    instance_arn = _launch_probe_instance(ctx)
    resource_scope = {"name": "ResourceArn", "value": instance_arn}

    co.put_recommendation_preferences(
        resourceType="Ec2Instance", scope=resource_scope, enhancedInfrastructureMetrics="Active"
    )
    ctx.on_cleanup(
        lambda: co.delete_recommendation_preferences(
            resourceType="Ec2Instance",
            scope=resource_scope,
            recommendationPreferenceNames=["EnhancedInfrastructureMetrics"],
        )
    )
    resp = co.get_effective_recommendation_preferences(resourceArn=instance_arn)
    assert resp["enhancedInfrastructureMetrics"] == "Active", (
        f"expected Active after put, got {resp['enhancedInfrastructureMetrics']!r}"
    )

    co.put_recommendation_preferences(
        resourceType="Ec2Instance", scope=resource_scope, enhancedInfrastructureMetrics="Inactive"
    )
    resp = co.get_effective_recommendation_preferences(resourceArn=instance_arn)
    assert resp["enhancedInfrastructureMetrics"] == "Inactive", (
        f"expected Inactive after put, got {resp['enhancedInfrastructureMetrics']!r}"
    )


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected success raises, so a
    target that accepts what AWS refuses fails loudly rather than as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _launch_probe_instance(ctx) -> str:
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    sts = ctx.client("sts")
    ami = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")[
        "Parameter"
    ]["Value"]
    name = ctx.unique_name("sim2real-co-probe-")
    resp = ec2.run_instances(
        ImageId=ami,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}],
        SubnetId=ctx.network().subnet_ids[0],
    )
    instance_id = resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))

    account_id = sts.get_caller_identity()["Account"]
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        try:
            desc = ec2.describe_instances(InstanceIds=[instance_id])
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
                raise
            time.sleep(3.0)
            continue
        reservations = desc.get("Reservations", [])
        if reservations and reservations[0]["Instances"]:
            return f"arn:aws:ec2:{ctx.region}:{account_id}:instance/{instance_id}"
        time.sleep(3.0)
    raise AssertionError("probe EC2 instance never became describable")


def _ensure_opted_in(co, timeout_s: float = 180.0, interval_s: float = 5.0) -> None:
    status = co.get_enrollment_status().get("status")
    if status != "Active":
        co.update_enrollment_status(status="Active")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = co.get_enrollment_status().get("status")
        if status == "Active":
            return
        time.sleep(interval_s)
    raise AssertionError(f"account never reached Active enrollment status, last={status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
