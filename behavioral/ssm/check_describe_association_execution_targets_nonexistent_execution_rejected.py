"""describe-association-execution-targets-nonexistent-execution-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-association-execution-targets-nonexistent-execution-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm"]

_DOC_NAME = "AWS-UpdateSSMAgent"
_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAssociationExecutionTargets succeeds for a real execution and returns an empty list
    for an unknown ExecutionId on a real association; an unknown AssociationId is rejected with
    AssociationDoesNotExist."""
    ssm = ctx.client("ssm")
    instance_id = _provision_connected_target(ctx)

    created = ssm.create_association(
        Name=_DOC_NAME,
        Targets=[{"Key": "InstanceIds", "Values": [instance_id]}],
        ApplyOnlyAtCronInterval=True,
        # ApplyOnlyAtCronInterval isn't supported for rate expressions -- use a cron instead.
        ScheduleExpression="cron(0 12 * * ? *)",
    )
    association_id = created["AssociationDescription"]["AssociationId"]
    ctx.on_cleanup(lambda: ssm.delete_association(AssociationId=association_id))

    ssm.start_associations_once(AssociationIds=[association_id])

    execution_id = _poll_until(
        lambda: ssm.describe_association_executions(AssociationId=association_id).get(
            "AssociationExecutions", []
        ),
        lambda execs: len(execs) >= 1,
        timeout_s=90.0,
        interval_s=3.0,
    )
    if not execution_id:
        raise AssertionError("no AssociationExecutions ever appeared for the started association")
    real_execution_id = execution_id[0]["ExecutionId"]

    # Positive control: a real execution id on a real association succeeds. Target resolution
    # can lag slightly behind the execution record appearing, so poll for it.
    targets = _poll_until(
        lambda: ssm.describe_association_execution_targets(
            AssociationId=association_id, ExecutionId=real_execution_id
        )["AssociationExecutionTargets"],
        lambda t: len(t) >= 1,
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert targets and len(targets) >= 1, "no AssociationExecutionTargets ever appeared for the execution"
    assert targets[0]["ResourceId"] == instance_id, (
        f"expected the execution target's ResourceId to be the real instance {instance_id}, "
        f"got {targets[0]['ResourceId']}"
    )

    # Negative: a well-formed but nonexistent AssociationId is rejected with
    # AssociationDoesNotExist -- this doesn't depend on any particular execution ever having
    # run (unlike a merely-unknown ExecutionId on a REAL association, which AWS tolerates and
    # answers with an empty target list rather than an error).
    bogus_association_id = str(uuid.uuid4())
    assert bogus_association_id != association_id, (
        "test bug: the random bogus id collided with the real association id"
    )
    code, message = _error(
        lambda: ssm.describe_association_execution_targets(
            AssociationId=bogus_association_id, ExecutionId=real_execution_id
        )
    )
    assert code == "AssociationDoesNotExist", code
    assert message == f"Association {bogus_association_id} does not exist.", message

    # Real association, unknown (but well-formed) execution id: AWS answers with an empty list
    # rather than an error.
    empty = ssm.describe_association_execution_targets(
        AssociationId=association_id, ExecutionId=str(uuid.uuid4())
    )
    assert empty["AssociationExecutionTargets"] == [], (
        "expected an unknown ExecutionId against a real association to resolve to an empty "
        f"target list, got {empty['AssociationExecutionTargets']}"
    )





def _error(fn):
    """Call fn() and return its error (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        if predicate(value):
            return value
        time.sleep(interval_s)
        value = probe()
    return value if predicate(value) else None


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

