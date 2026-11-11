"""compliance-items-put-overwrite-last-write-wins."""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "compliance-items-put-overwrite-last-write-wins"
GROUP = "concurrency"
SERVICES = ["ssm"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A second PutComplianceItems for the same resource and ComplianceType fully supersedes the
    first: ListComplianceItems shows only the later execution's single item.
    """
    ssm = ctx.client("ssm")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")

    # PutComplianceItems rejects a ResourceId that is not a registered, online managed node.
    instance_id = _provision_managed_node(ctx, ssm, ec2, iam)

    # Distinct Custom: compliance type names count against a cumulative account limit with no
    # release API; the fresh ResourceId already isolates runs, so a fixed name is reused.
    compliance_type = "Custom:Sim2RealOverwrite"
    exec_id_1 = f"exec1{uuid.uuid4().hex[:8]}"
    exec_id_2 = f"exec2{uuid.uuid4().hex[:8]}"
    t1 = datetime.now(timezone.utc) - timedelta(minutes=5)
    t2 = datetime.now(timezone.utc)

    ssm.put_compliance_items(
        ResourceId=instance_id,
        ResourceType="ManagedInstance",
        ComplianceType=compliance_type,
        ExecutionSummary={"ExecutionTime": t1, "ExecutionId": exec_id_1, "ExecutionType": "Command"},
        Items=[{"Id": "check-1", "Title": "Initial", "Severity": "LOW", "Status": "COMPLIANT"}],
    )
    ssm.put_compliance_items(
        ResourceId=instance_id,
        ResourceType="ManagedInstance",
        ComplianceType=compliance_type,
        ExecutionSummary={"ExecutionTime": t2, "ExecutionId": exec_id_2, "ExecutionType": "Command"},
        Items=[{"Id": "check-1", "Title": "Updated", "Severity": "CRITICAL", "Status": "NON_COMPLIANT"}],
    )

    items = _poll_until_execution(ssm, instance_id, compliance_type, exec_id_2, timeout_s=60.0)
    assert len(items) == 1, f"expected exactly one surviving item after overwrite, got {items}"
    item = items[0]
    assert item["ExecutionSummary"]["ExecutionId"] == exec_id_2
    assert item["Status"] == "NON_COMPLIANT", f"stale (first-write) status leaked through: {item}"
    assert item["Title"] == "Updated"


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

    role_name = ctx.unique_name("sim2real-compl-role-")[:64]
    profile_name = ctx.unique_name("sim2real-compl-prof-")[:128]
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
                    "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-compl-node-")}],
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


def _poll_until_execution(ssm, resource_id, compliance_type, expected_exec_id, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_items = []
    while time.monotonic() < deadline:
        resp = ssm.list_compliance_items(
            ResourceIds=[resource_id],
            ResourceTypes=["ManagedInstance"],
            Filters=[{"Key": "ComplianceType", "Values": [compliance_type]}],
        )
        last_items = resp.get("ComplianceItems", [])
        if any(i.get("ExecutionSummary", {}).get("ExecutionId") == expected_exec_id for i in last_items):
            return last_items
        time.sleep(interval_s)
    raise AssertionError(
        f"ListComplianceItems never reflected the later execution {expected_exec_id!r} "
        f"within {timeout_s}s; last seen: {last_items}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
