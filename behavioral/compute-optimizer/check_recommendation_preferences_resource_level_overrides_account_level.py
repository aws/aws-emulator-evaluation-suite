"""recommendation-preferences-resource-level-overrides-account-level."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "recommendation-preferences-resource-level-overrides-account-level"
GROUP = "state-machine"
SERVICES = ["compute-optimizer"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx) -> None:
    """With an account-level DAYS_93 and a resource-level DAYS_32 lookBackPeriod for one EC2 instance,
    GetEffectiveRecommendationPreferences reports DAYS_32, also after the account-level entry is
    rewritten last."""
    co = ctx.client("compute-optimizer")
    _ensure_opted_in(co)
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    instance_arn = _launch_probe_instance(ctx)

    account_scope = {"name": "AccountId", "value": account_id}
    resource_scope = {"name": "ResourceArn", "value": instance_arn}

    # The account-scoped preference is a per-account singleton: snapshot it and restore it.
    prior = co.get_recommendation_preferences(resourceType="Ec2Instance", scope=account_scope)
    prior_lookback = next(
        (d.get("lookBackPeriod") for d in prior.get("recommendationPreferencesDetails", [])
         if d.get("scope") == account_scope and d.get("lookBackPeriod")),
        None,
    )

    co.put_recommendation_preferences(
        resourceType="Ec2Instance", scope=account_scope, lookBackPeriod="DAYS_93"
    )

    def _restore_account_scope():
        if prior_lookback:
            co.put_recommendation_preferences(
                resourceType="Ec2Instance", scope=account_scope, lookBackPeriod=prior_lookback
            )
        else:
            co.delete_recommendation_preferences(
                resourceType="Ec2Instance", scope=account_scope,
                recommendationPreferenceNames=["LookBackPeriodPreference"],
            )

    ctx.on_cleanup(_restore_account_scope)

    # Positive control: with only the account-level entry set, the effective value
    # must already be the account-level one -- proves the account scope actually
    # takes effect here, rather than the target ignoring PutRecommendationPreferences
    # entirely and always echoing some other default.
    before_resource_scope = co.get_effective_recommendation_preferences(resourceArn=instance_arn)
    assert before_resource_scope["lookBackPeriod"] == "DAYS_93", (
        f"expected account-level DAYS_93 before any resource-level entry exists, "
        f"got {before_resource_scope['lookBackPeriod']!r}"
    )

    co.put_recommendation_preferences(
        resourceType="Ec2Instance", scope=resource_scope, lookBackPeriod="DAYS_32"
    )
    ctx.on_cleanup(
        lambda: co.delete_recommendation_preferences(
            resourceType="Ec2Instance", scope=resource_scope, recommendationPreferenceNames=["LookBackPeriodPreference"]
        )
    )

    effective = co.get_effective_recommendation_preferences(resourceArn=instance_arn)
    assert effective["lookBackPeriod"] == "DAYS_32", (
        f"expected resource-level DAYS_32 to override account-level DAYS_93, "
        f"got {effective['lookBackPeriod']!r}"
    )

    # Rewrite the account-level entry *after* the resource-level one, to a third
    # value. If precedence were actually recency ("most recent write wins"), the
    # effective value would now flip to the account-level DAYS_14. Real scope-based
    # precedence must keep reporting the resource-level DAYS_32 regardless.
    co.put_recommendation_preferences(
        resourceType="Ec2Instance", scope=account_scope, lookBackPeriod="DAYS_14"
    )
    effective_after_recency_flip = co.get_effective_recommendation_preferences(resourceArn=instance_arn)
    assert effective_after_recency_flip["lookBackPeriod"] == "DAYS_32", (
        f"resource-level DAYS_32 must still win after account-level was rewritten more "
        f"recently to DAYS_14 -- precedence must be scope-based, not recency-based, "
        f"got {effective_after_recency_flip['lookBackPeriod']!r}"
    )


def _launch_probe_instance(ctx) -> str:
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    sts = ctx.client("sts")
    ami = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")[
        "Parameter"
    ]["Value"]
    name = ctx.unique_name("sim2real-co-probe-")
    subnet_id = _create_subnet(ctx, ec2, name)
    resp = ec2.run_instances(
        ImageId=ami,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    instance_id = resp["Instances"][0]["InstanceId"]

    def _terminate():
        ec2.terminate_instances(InstanceIds=[instance_id])
        # Bounded poll, not the botocore waiter: that waiter fails on "pending", which a
        # just-launched instance still reports when terminated straight away.
        deadline = time.monotonic() + 300.0
        state = None
        while time.monotonic() < deadline:
            reservations = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
            state = reservations[0]["Instances"][0]["State"]["Name"]
            if state == "terminated":
                return
            time.sleep(5.0)
        raise AssertionError(f"instance {instance_id} never terminated, last state={state!r}")

    ctx.on_cleanup(_terminate)

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


def _create_subnet(ctx, ec2, name: str) -> str:
    """A VPC and subnet this check owns, in an AZ that offers the probe instance type."""
    offered = ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": ["t3.micro"]}],
    )["InstanceTypeOfferings"]
    assert offered, "t3.micro is offered in no availability zone of this region"
    az = sorted(o["Location"] for o in offered)[0]
    tags = [{"Key": "Name", "Value": name}]
    vpc_id = ec2.create_vpc(
        CidrBlock="10.0.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": tags}]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.0.1.0/24", AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tags}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    return subnet_id


def _ensure_opted_in(co, timeout_s: float = 180.0, interval_s: float = 5.0) -> None:
    """Opt the account in as a precondition, and leave it opted in.

    Enrollment is deliberately not restored: after an opt-out AWS refuses an opt-in for 24
    hours ("Cannot opt-in within 24 hours of opt-out"), so a restore would fail every later
    check in the account for a day.
    """
    status = co.get_enrollment_status()["status"]
    if status == "Active":
        return
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
