"""put-compliance-items-then-list-roundtrip."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-compliance-items-then-list-roundtrip"
GROUP = "state-machine"
SERVICES = ["ssm"]

_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutComplianceItems on a managed node makes the item listable via ListComplianceItems
    with matching Id, Severity, Status, ResourceId and ComplianceType."""
    ssm = ctx.client("ssm")
    # AWS validates ResourceId against a registered ManagedInstance, so a real node is needed.
    resource_id = _provision_connected_targets(ctx, count=1)[0]

    # The account caps distinct Custom: ComplianceType names ever used
    # (ComplianceTypeCountLimitExceededException), so an existing sub-type is reused.
    compliance_type = _pick_reusable_custom_compliance_type(ssm)
    items = [
        {
            "Id": "item-1",
            "Title": "sim2real compliance roundtrip",
            "Severity": "HIGH",
            "Status": "NON_COMPLIANT",
        }
    ]
    execution_summary = {"ExecutionTime": datetime.now(timezone.utc)}

    def _cleanup() -> None:
        try:
            ssm.put_compliance_items(
                ResourceId=resource_id,
                ResourceType="ManagedInstance",
                ComplianceType=compliance_type,
                ExecutionSummary={"ExecutionTime": datetime.now(timezone.utc)},
                Items=[],
            )
        except ClientError as err:
            # The node is already deregistered, so it carries no compliance data to clear.
            if err.response["Error"]["Code"] != "InvalidResourceId":
                raise

    ctx.on_cleanup(_cleanup)

    ssm.put_compliance_items(
        ResourceId=resource_id,
        ResourceType="ManagedInstance",
        ComplianceType=compliance_type,
        ExecutionSummary=execution_summary,
        Items=items,
    )

    resp = _poll_until(
        lambda: ssm.list_compliance_items(
            ResourceIds=[resource_id],
            Filters=[{"Key": "ComplianceType", "Values": [compliance_type]}],
        ),
        lambda r: len(r["ComplianceItems"]) >= 1,
        timeout_s=_budget_s(ctx, 60.0),
        interval_s=2.0,
        ctx=ctx,
    )
    found = resp["ComplianceItems"]
    assert len(found) == 1, f"expected exactly one compliance item, got {found}"
    entry = found[0]
    assert entry["Id"] == "item-1", f"expected Id=item-1, got {entry['Id']!r}"
    assert entry["Severity"] == "HIGH", f"expected Severity=HIGH, got {entry['Severity']!r}"
    assert entry["Status"] == "NON_COMPLIANT", (
        f"expected Status=NON_COMPLIANT, got {entry['Status']!r}"
    )
    assert entry["ResourceId"] == resource_id, (
        f"expected ResourceId={resource_id!r}, got {entry['ResourceId']!r}"
    )
    assert entry["ComplianceType"] == compliance_type, (
        f"expected ComplianceType={compliance_type!r}, got {entry['ComplianceType']!r}"
    )


# ===== helpers =====

def _poll_until(probe, predicate, *, timeout_s: float = 30.0, interval_s: float = 1.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("the polled condition: the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")

_BOOTSTRAP_CUSTOM_COMPLIANCE_TYPE = "Custom:Sim2realRoundtrip"


def _pick_reusable_custom_compliance_type(ssm) -> str:
    """Return a registered Custom: sub-type of AWS:ComplianceItem, else one fixed name.

    The account caps distinct sub-type names with no API to free one, so a fixed fallback is
    minted at most once."""
    resp = ssm.get_inventory_schema(TypeName="AWS:ComplianceItem", SubType=True)
    for schema in resp.get("Schemas", []):
        name = schema.get("TypeName", "")
        if name.startswith("Custom:"):
            return name
    return _BOOTSTRAP_CUSTOM_COMPLIANCE_TYPE


def _provision_connected_targets(ctx, count: int = 1) -> list[str]:
    """Launch `count` EC2 instances with AmazonSSMManagedInstanceCore; wait until all are Online
    in SSM and return their ids."""
    iam = ctx.client("iam")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    role_name = ctx.unique_name("sim2real-behav-ssm-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY_ARN)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_CORE_POLICY_ARN)
    )

    profile_name = ctx.unique_name("sim2real-behav-ssm-profile-")
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=profile_name, RoleName=role_name
        )
    )

    ami_id = ssm.get_parameter(Name=_AMI_PARAM)["Parameter"]["Value"]
    name_tag = ctx.unique_name("sim2real-behav-ssm-target-")

    instance_ids: list[str] = []
    last_err = None
    deadline = time.monotonic() + _budget_s(ctx, 90)
    while not instance_ids and time.monotonic() < deadline:
        try:
            run_resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=count,
                MaxCount=count,
                IamInstanceProfile={"Name": profile_name},
                TagSpecifications=[
                    {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name_tag}]}
                ],
                SubnetId=ctx.network().subnet_ids[0],
            )
            instance_ids = [i["InstanceId"] for i in run_resp["Instances"]]
        except ClientError as exc:
            last_err = exc
            if exc.response["Error"]["Code"] not in (
                "InvalidParameterValue",
                "InvalidParameterValueError",
            ):
                raise
            time.sleep(2)
    if not instance_ids:
        if _budget_spent(ctx):
            raise TimeoutError("RunInstances accepting the instance profile: the run budget ended first; "
                               "not graded")
        raise AssertionError(f"run_instances never succeeded after IAM propagation: {last_err}")
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=instance_ids))

    _wait_instances(ec2, instance_ids, "running", _budget_s(ctx, 600.0), ctx=ctx)

    deadline = time.monotonic() + _budget_s(ctx, 600)
    pending = set(instance_ids)
    while pending and time.monotonic() < deadline:
        info = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": list(pending)}]
        )["InstanceInformationList"]
        online = {i["InstanceId"] for i in info if i.get("PingStatus") == "Online"}
        pending -= online
        if pending:
            time.sleep(2)
    if pending:
        if _budget_spent(ctx):
            raise TimeoutError(f"instances {pending} reaching PingStatus=Online: the run budget ended first; "
                               "not graded")
        raise AssertionError(f"instances {pending} never reached SSM PingStatus=Online in time")
    return instance_ids


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
