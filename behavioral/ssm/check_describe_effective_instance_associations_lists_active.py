"""describe-effective-instance-associations-lists-active."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-effective-instance-associations-lists-active"
GROUP = "error-semantics"
SERVICES = ["ssm"]

_DOC_NAME = "AWS-UpdateSSMAgent"
# Fires only on Feb 29 (leap years) -- effectively never during a test run.
_FAR_FUTURE_CRON = "cron(0 0 29 2 ? *)"
_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeEffectiveInstanceAssociations returns exactly the InstanceId-created association
    effective for a registered managed node, and an empty list (not an error) for an unknown id."""
    ssm = ctx.client("ssm")
    instance_id = _provision_connected_target(ctx)
    doc_name = _create_legacy_document(ctx)

    created = ssm.create_association(
        Name=doc_name,
        InstanceId=instance_id,
        # NOTE: ScheduleExpression/ApplyOnlyAtCronInterval are not supported together with the
        # legacy InstanceId parameter -- AWS rejects the combination with ValidationException.
    )
    association_id = created["AssociationDescription"]["AssociationId"]
    ctx.on_cleanup(
        lambda: ssm.delete_association(Name=doc_name, InstanceId=instance_id)
    )

    effective = _poll_until(
        lambda: ssm.describe_effective_instance_associations(InstanceId=instance_id)["Associations"],
        lambda assocs: any(a["AssociationId"] == association_id for a in assocs),
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert len(effective) == 1, f"expected exactly 1 effective association, got {effective}"
    assert effective[0]["AssociationId"] == association_id, (
        f"expected effective association id {association_id!r}, got {effective[0]['AssociationId']!r}"
    )
    assert effective[0]["InstanceId"] == instance_id, (
        f"expected effective association bound to {instance_id!r}, got {effective[0]['InstanceId']!r}"
    )
    assert effective[0]["Content"], "Content should carry the rendered document body"

    # Negative: a syntactically valid but never-registered managed node id is tolerated --
    # this lookup returns an empty list rather than validating managed-node existence.
    unregistered = ssm.describe_effective_instance_associations(InstanceId="i-00000000000000000")
    assert unregistered["Associations"] == [], (
        f"expected no effective associations for a never-registered node, got {unregistered['Associations']}"
    )





def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        if predicate(value):
            return value
        time.sleep(interval_s)
        value = probe()
    raise AssertionError(f"condition never became true within {timeout_s}s; last value: {value}")


def _create_legacy_document(ctx) -> str:
    """Create a minimal schema-1.2 Command document for the InstanceId association path.
    AWS-owned documents use a newer schema that this path rejects with InvalidDocument."""
    ssm = ctx.client("ssm")
    doc_name = ctx.unique_name("sim2real-behav-legacy-doc-")
    content = json.dumps(
        {
            "schemaVersion": "1.2",
            "description": "sim2real-behav legacy (schema 1.2) document for InstanceId "
            "association tests",
            "runtimeConfig": {
                "aws:runShellScript": {
                    "properties": [
                        {"id": "0.aws:runShellScript", "runCommand": ["echo sim2real-behav"]}
                    ]
                }
            },
        }
    )
    ssm.create_document(Name=doc_name, Content=content, DocumentType="Command", DocumentFormat="JSON")
    ctx.on_cleanup(lambda: ssm.delete_document(Name=doc_name))
    return doc_name



def _provision_connected_target(ctx) -> str:
    """Create an IAM role + instance profile with AmazonSSMManagedInstanceCore, launch one EC2
    instance, and wait until it registers Online with Systems Manager. Returns its InstanceId."""
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
    deadline = time.monotonic() + 90
    while not instance_ids and time.monotonic() < deadline:
        try:
            run_resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
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
            time.sleep(5)
    if not instance_ids:
        raise AssertionError(f"run_instances never succeeded after IAM propagation: {last_err}")
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=instance_ids))

    ec2.get_waiter("instance_running").wait(InstanceIds=instance_ids, WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    left = ctx.time_left()
    deadline = time.monotonic() + (600 if left is None else min(600, left))
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
        raise AssertionError(f"instances {pending} never reached SSM PingStatus=Online in time")
    return instance_ids[0]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

