"""compliance-items-invalid-resource-type-rejected."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "compliance-items-invalid-resource-type-rejected"
GROUP = "server-side"
SERVICES = ["ssm"]

_FALLBACK_COMPLIANCE_TYPE = "Custom:Sim2RealPrecision"
_SUMMARY_GRADED_TYPES = ("Custom:Sim2RealSummaryByStatus", "Custom:Sim2RealAggregation")

_SSM_MANAGED_POLICY = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutComplianceItems rejects a ResourceType other than ManagedInstance with InvalidResourceType
    and creates no compliance record, while the identical ManagedInstance call succeeds."""
    ssm = ctx.client("ssm")
    # Put/ListComplianceItems reject an unregistered ResourceId (even a well-formed i-<hex>) with
    # InvalidResourceId, so this waits for a real instance's SSM Agent to register.
    resource_id = _launch_ssm_managed_instance(ctx)


    # A Custom: ComplianceType name is a permanent registration counted against an account-wide
    # cap with no API to release it, so a registered one is reused; every read is scoped to the
    # fresh managed node, which keeps runs apart.
    compliance_type = _pick_custom_compliance_type(ssm)
    now = datetime.now(timezone.utc)

    code, message = _error(
        lambda: ssm.put_compliance_items(
            ResourceId=resource_id,
            ResourceType="NotARealResourceType",
            ComplianceType=compliance_type,
            ExecutionSummary={"ExecutionTime": now},
            Items=[{"Id": "item-1", "Severity": "HIGH", "Status": "NON_COMPLIANT"}],
        )
    )
    assert code == "InvalidResourceType", code
    assert message == (
        "Resource type NotARealResourceType is not supported, example resource type are "
        "[ManagedInstance]"
    ), message

    # (b) the rejected call must not have created anything under this ComplianceType
    # for the real resource -- listing is scoped by ComplianceType via the returned items' field.
    leaked_items = [
        item
        for item in ssm.list_compliance_items(ResourceIds=[resource_id])["ComplianceItems"]
        if item.get("ComplianceType") == compliance_type
    ]
    assert leaked_items == [], leaked_items

    # (c) positive control: the identical shape of call succeeds with the supported ResourceType.
    ssm.put_compliance_items(
        ResourceId=resource_id,
        ResourceType="ManagedInstance",
        ComplianceType=compliance_type,
        ExecutionSummary={"ExecutionTime": now},
        Items=[{"Id": "item-2", "Severity": "HIGH", "Status": "NON_COMPLIANT"}],
    )
    ctx.on_cleanup(
        lambda: ssm.put_compliance_items(
            ResourceId=resource_id,
            ResourceType="ManagedInstance",
            ComplianceType=compliance_type,
            ExecutionSummary={"ExecutionTime": datetime.now(timezone.utc)},
            Items=[],
        )
    )

    good_items = _poll_for_items(ssm, resource_id, compliance_type, timeout_s=30.0)
    assert len(good_items) == 1 and good_items[0]["Id"] == "item-2", good_items


def _pick_custom_compliance_type(ssm) -> str:
    """Return a registered Custom: compliance sub-type, else one shared fallback name. Names whose
    account-wide summaries other checks grade by delta are never written."""
    resp = ssm.get_inventory_schema(TypeName="AWS:ComplianceItem", SubType=True)
    for schema in resp.get("Schemas", []):
        name = schema.get("TypeName", "")
        if name.startswith("Custom:") and not name.startswith(_SUMMARY_GRADED_TYPES):
            return name
    return _FALLBACK_COMPLIANCE_TYPE


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call unexpectedly succeeded: {result!r}")


def _poll_for_items(ssm, resource_id: str, compliance_type: str, timeout_s: float):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        items = [
            item
            for item in ssm.list_compliance_items(ResourceIds=[resource_id])["ComplianceItems"]
            if item.get("ComplianceType") == compliance_type
        ]
        if items:
            return items
        time.sleep(3.0)
    return []


def _wait_for_agent_online(
    ctx, instance_id: str, timeout_s: float = 600.0, interval_s: float = 15.0
) -> None:
    ssm = ctx.client("ssm")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )
        infos = resp.get("InstanceInformationList", [])
        if infos and infos[0].get("PingStatus") == "Online":
            return
        time.sleep(interval_s)
    raise AssertionError(
        f"instance {instance_id} never reached PingStatus=Online (SSM Agent never registered)"
    )


def _launch_ssm_managed_instance(ctx, extra_tags=None) -> str:
    from botocore.exceptions import ClientError

    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    ssm = ctx.client("ssm")

    role_name = ctx.unique_name("sim2real-ssmrole-")
    trust = json.dumps(
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
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SSM_MANAGED_POLICY)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_SSM_MANAGED_POLICY)
    )

    profile_name = ctx.unique_name("sim2real-ssmprof-")
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=profile_name, RoleName=role_name
        )
    )

    ami_id = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")[
        "Parameter"
    ]["Value"]

    tags = [{"Key": "Name", "Value": ctx.unique_name("sim2real-ssm-node-")}]
    if extra_tags:
        tags.extend(extra_tags)

    # EC2 rejects a just-created instance profile with InvalidParameterValue until IAM's
    # role/instance-profile propagation catches up -- bounded retry, not a fixed wait.
    instance_id = None
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        try:
            resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                IamInstanceProfile={"Name": profile_name},
                TagSpecifications=[{"ResourceType": "instance", "Tags": tags}],
                SubnetId=ctx.network().subnet_ids[0],
            )
            instance_id = resp["Instances"][0]["InstanceId"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterValue":
                time.sleep(5.0)
                continue
            raise
    if instance_id is None:
        raise AssertionError("could not launch an EC2 instance for the SSM managed node")
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))

    _wait_for_agent_online(ctx, instance_id)
    return instance_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
