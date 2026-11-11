"""compliance-item-timestamp-precision-preserved."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "compliance-item-timestamp-precision-preserved"
GROUP = "representation"
SERVICES = ["ssm"]

_FALLBACK_COMPLIANCE_TYPE = "Custom:Sim2RealPrecision"
_SUMMARY_GRADED_TYPES = ("Custom:Sim2RealSummaryByStatus", "Custom:Sim2RealAggregation")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListComplianceItems returns the PutComplianceItems execution time exactly, to the second,
    not rounded to a coarser boundary or replaced with the server's receipt time."""
    ssm = ctx.client("ssm")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    # PutComplianceItems rejects a never-registered ResourceId with InvalidResourceId, so a real
    # managed node is provisioned.
    resource_id = _provision_managed_node(ctx, ssm, ec2, iam)

    # A deliberately non-round instant: 3h17m43s in the past, second precision.
    execution_time = (datetime.now(timezone.utc) - timedelta(hours=3, minutes=17, seconds=43)).replace(
        microsecond=0
    )
    # A Custom: ComplianceType name is a permanent registration counted against an account-wide
    # cap with no API to release it, so a registered one is reused; every read is scoped to the
    # fresh managed node, which keeps runs apart.
    compliance_type = _pick_custom_compliance_type(ssm)

    ssm.put_compliance_items(
        ResourceId=resource_id,
        ResourceType="ManagedInstance",
        ComplianceType=compliance_type,
        ExecutionSummary={
            "ExecutionTime": execution_time,
            "ExecutionId": "sim2real-ts-exec",
            "ExecutionType": "Command",
        },
        Items=[
            {
                "Id": "TS0000001",
                "Title": "sim2real timestamp precision item",
                "Severity": "LOW",
                "Status": "COMPLIANT",
            }
        ],
    )

    def _fetch_matching():
        items = ssm.list_compliance_items(
            ResourceIds=[resource_id],
            Filters=[{"Key": "ComplianceType", "Values": [compliance_type]}],
        )["ComplianceItems"]
        return [i for i in items if i["Id"] == "TS0000001"]

    matching = _poll_until(_fetch_matching, lambda m: len(m) == 1, timeout_s=60.0, interval_s=3.0)
    assert len(matching) == 1, f"expected exactly one compliance item TS0000001, got {matching!r}"
    returned_time = matching[0]["ExecutionSummary"]["ExecutionTime"]
    assert returned_time == execution_time, (returned_time, execution_time)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)


def _pick_custom_compliance_type(ssm) -> str:
    """Return a registered Custom: compliance sub-type, else one shared fallback name. Names whose
    account-wide summaries other checks grade by delta are never written."""
    resp = ssm.get_inventory_schema(TypeName="AWS:ComplianceItem", SubType=True)
    for schema in resp.get("Schemas", []):
        name = schema.get("TypeName", "")
        if name.startswith("Custom:") and not name.startswith(_SUMMARY_GRADED_TYPES):
            return name
    return _FALLBACK_COMPLIANCE_TYPE


def _provision_managed_node(ctx, ssm, ec2, iam) -> str:
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(
            "No shared network VPC in this account/region to launch a managed EC2 node "
            "into; PutComplianceItems needs a real, registered managed node."
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("Shared network has no subnets to launch into.")
    subnet_id = subnets[0]["SubnetId"]

    role_name = ctx.unique_name("sim2real-ts-role-")[:64]
    profile_name = ctx.unique_name("sim2real-ts-prof-")[:128]
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)
    ctx.on_cleanup(lambda: _safe_delete_role(iam, role_name))
    managed_policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
    ctx.on_cleanup(lambda: _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)))
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: _safe_delete_instance_profile(iam, profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: _safe(lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=profile_name, RoleName=role_name
        ))
    )

    ami_id = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]

    instance_id = _retry_on_profile_propagation(
        lambda: ec2.run_instances(
            ImageId=ami_id,
            InstanceType="t3.micro",
            MinCount=1,
            MaxCount=1,
            SubnetId=subnet_id,
            IamInstanceProfile={"Name": profile_name},
            TagSpecifications=[
                {
                    "ResourceType": "instance",
                    "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-ts-node-")}],
                }
            ],
        )["Instances"][0]["InstanceId"]
    )
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))

    _poll_until(
        lambda: _describe_instance_state(ec2, instance_id),
        lambda state: state == "running",
        timeout_s=180.0,
        interval_s=5.0,
    )
    _poll_until(
        lambda: _ping_status(ssm, instance_id),
        lambda status: status == "Online",
        timeout_s=420.0,
        interval_s=10.0,
    )
    return instance_id


def _describe_instance_state(ec2, instance_id):
    try:
        return ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]["State"]["Name"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
            return None
        raise


def _ping_status(ssm, instance_id):
    page = ssm.describe_instance_information(Filters=[{"Key": "InstanceIds", "Values": [instance_id]}])
    infos = page.get("InstanceInformationList", [])
    if not infos:
        return None
    return infos[0].get("PingStatus")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


def _retry_on_profile_propagation(fn, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = err.response["Error"].get("Message", "").lower()
            if code == "InvalidParameterValue" and "invalid iam instance profile" in msg:
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    raise last_err


def _safe(fn):
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("NoSuchEntity", "LimitExceeded"):
            raise


def _safe_delete_role(iam, role_name):
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _safe_delete_instance_profile(iam, profile_name):
    try:
        iam.delete_instance_profile(InstanceProfileName=profile_name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise

