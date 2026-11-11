"""effective-recommendation-preferences-for-real-ec2-instance."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "effective-recommendation-preferences-for-real-ec2-instance"
GROUP = "data-plane"
SERVICES = ["compute-optimizer"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx) -> None:
    """GetEffectiveRecommendationPreferences for a real EC2 instance with no resource-level preference reports
    the account-scope enhancedInfrastructureMetrics and lookBackPeriod on record, or the defaults Inactive and
    DAYS_14 when none is."""
    co = ctx.client("compute-optimizer")
    _ensure_opted_in(co)
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    instance_arn = _launch_probe_instance(ctx)

    resp = co.get_effective_recommendation_preferences(resourceArn=instance_arn)

    account_detail = _find_detail(co, "Ec2Instance", {"name": "AccountId", "value": account_id})
    expected_metrics = (account_detail or {}).get("enhancedInfrastructureMetrics", "Inactive")
    expected_lookback = (account_detail or {}).get("lookBackPeriod", "DAYS_14")

    assert resp["enhancedInfrastructureMetrics"] == expected_metrics, (
        f"effective enhancedInfrastructureMetrics={resp['enhancedInfrastructureMetrics']!r} for a "
        f"resource with no resource-level override, expected={expected_metrics!r} "
        f"(the account-scope preference on record, or the Inactive default when none is)"
    )
    assert resp["lookBackPeriod"] == expected_lookback, (
        f"effective lookBackPeriod={resp['lookBackPeriod']!r} for a resource with no resource-level "
        f"override, expected={expected_lookback!r} "
        f"(the account-scope preference on record, or the DAYS_14 default when none is)"
    )


def _find_detail(co, resource_type, scope):
    resp = co.get_recommendation_preferences(resourceType=resource_type, scope=scope)
    for detail in resp.get("recommendationPreferencesDetails", []):
        if detail.get("scope", {}).get("name") == scope["name"] and detail.get("scope", {}).get("value") == scope["value"]:
            return detail
    return None

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
