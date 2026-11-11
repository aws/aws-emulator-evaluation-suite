"""compliance-item-empty-vs-absent-details-preserved."""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "compliance-item-empty-vs-absent-details-preserved"
GROUP = "state-machine"
SERVICES = ["ssm"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListComplianceItems returns Details == {} both for an item put with an empty Details map
    and for one put with no Details field; AWS does not keep the two distinct."""
    ssm = ctx.client("ssm")
    resource_id = _provision_ssm_managed_instance(ctx)
    resource_type = "ManagedInstance"
    compliance_type = "Custom:DetailsPreservation"

    ssm.put_compliance_items(
        ResourceId=resource_id,
        ResourceType=resource_type,
        ComplianceType=compliance_type,
        ExecutionSummary={"ExecutionTime": datetime.now(timezone.utc)},
        Items=[
            {
                "Id": "empty-details-item",
                "Severity": "LOW",
                "Status": "COMPLIANT",
                "Details": {},
            },
            {
                "Id": "absent-details-item",
                "Severity": "LOW",
                "Status": "COMPLIANT",
            },
        ],
    )

    resp = _poll_until(
        lambda: ssm.list_compliance_items(ResourceIds=[resource_id], ResourceTypes=[resource_type]),
        lambda r: {"empty-details-item", "absent-details-item"}
        <= {item["Id"] for item in r["ComplianceItems"]},
        timeout_s=_budget_s(ctx, 60.0),
        interval_s=2.0,
        ctx=ctx,
    )
    by_id = {item["Id"]: item for item in resp["ComplianceItems"]}
    assert "empty-details-item" in by_id, "explicit-empty-details item missing from listing"
    assert "absent-details-item" in by_id, "absent-details item missing from listing"

    empty_item = by_id["empty-details-item"]
    absent_item = by_id["absent-details-item"]

    assert "Details" in empty_item, "an explicitly-empty Details map was dropped entirely"
    assert empty_item["Details"] == {}, empty_item["Details"]

    assert "Details" in absent_item, (
        "an absent Details field should be normalized to an explicit empty map by real AWS, "
        f"but the key was missing entirely: {absent_item!r}"
    )
    assert absent_item["Details"] == {}, (
        f"an absent Details field should normalize to {{}}, got {absent_item['Details']!r}"
    )


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float,
    ctx=None,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("the polled condition: the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _provision_ssm_managed_instance(ctx) -> str:
    """Launch a minimal EC2 instance with an SSM instance profile and wait for it to
    register with SSM as an Online managed node."""
    iam = ctx.client("iam")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    role_name = ctx.unique_name("sim2real-ssm-role-")
    profile_name = ctx.unique_name("sim2real-ssm-profile-")
    trust_policy = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    )
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(
        lambda: _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    )
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(
        lambda: _safe(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    )
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: _safe(
            lambda: iam.remove_role_from_instance_profile(
                InstanceProfileName=profile_name, RoleName=role_name
            )
        )
    )

    ami_id = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
    )["Parameter"]["Value"]

    instance_id = None
    deadline = time.monotonic() + _budget_s(ctx, 90)
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                IamInstanceProfile={"Name": profile_name},
                TagSpecifications=[
                    {
                        "ResourceType": "instance",
                        "Tags": [
                            {"Key": "Name", "Value": ctx.unique_name("sim2real-ssm-managed-")}
                        ],
                    }
                ],
                SubnetId=ctx.network().subnet_ids[0],
            )
            instance_id = resp["Instances"][0]["InstanceId"]
            break
        except Exception as exc:  # IAM instance-profile propagation lag
            last_error = exc
            time.sleep(2)
    if instance_id is None:
        if _budget_spent(ctx):
            raise TimeoutError("RunInstances accepting the instance profile: the run budget ended first; not graded")
        raise AssertionError(f"could not launch instance (IAM propagation?): {last_error}")

    ctx.on_cleanup(lambda: _safe(lambda: ec2.terminate_instances(InstanceIds=[instance_id])))
    _wait_instances(ec2, [instance_id], "running", _budget_s(ctx, 600.0), ctx=ctx)

    _poll_until(
        lambda: ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        ).get("InstanceInformationList", []),
        lambda infos: bool(infos) and infos[0].get("PingStatus") == "Online",
        timeout_s=_budget_s(ctx, 600),
        interval_s=2.0,
        ctx=ctx,
    )
    return instance_id


def _safe(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("InvalidInstanceID.NotFound", "NoSuchEntity"):
            raise


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_instances(ec2, instance_ids, want: str, timeout_s: float, *, strict: bool = True, ctx=None) -> None:
    """Poll every 1 s until every instance is in state want; a strict wait fails on a dead end."""
    dead = {"running": ("shutting-down", "terminated", "stopping", "stopped")}.get(want, ())
    deadline = time.monotonic() + timeout_s
    states = {}
    while True:
        try:
            reservations = ec2.describe_instances(InstanceIds=list(instance_ids))["Reservations"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
                raise
            reservations = []
        states = {i["InstanceId"]: i["State"]["Name"] for r in reservations for i in r["Instances"]}
        if len(states) == len(instance_ids) and all(s == want for s in states.values()):
            return
        if not strict:
            if time.monotonic() >= deadline:
                return
        else:
            assert not any(s in dead for s in states.values()), (
                f"instances {list(instance_ids)} reached {states!r} instead of {want!r}")
            if time.monotonic() >= deadline and ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"instances reaching {want!r}: the run budget ended first; not graded")
            assert time.monotonic() < deadline, (
                f"instances {list(instance_ids)} not {want!r} in time: {states!r}")
        time.sleep(1.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
