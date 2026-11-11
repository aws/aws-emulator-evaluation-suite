"""session-start-status-terminate-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "session-start-status-terminate-lifecycle"
GROUP = "state-machine"
SERVICES = ["ssm"]

_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartSession establishes a session (agent Connected), TerminateSession moves it
    to History with a terminal Status, observed end-to-end against a real SSM-managed node."""
    instance_id = _provision_connected_target(ctx)
    ssm = ctx.client("ssm")

    status = ssm.get_connection_status(Target=instance_id)["Status"]
    assert status == "connected", f"expected agent connected before StartSession, got {status}"

    start_resp = ssm.start_session(Target=instance_id)
    session_id = start_resp["SessionId"]
    assert start_resp["StreamUrl"], "StartSession did not return a StreamUrl"
    ctx.on_cleanup(lambda: _best_effort_terminate(ssm, session_id))

    term_resp = ssm.terminate_session(SessionId=session_id)
    assert term_resp["SessionId"] == session_id, (
        f"TerminateSession echoed SessionId={term_resp['SessionId']!r}, expected {session_id!r}"
    )

    history = _poll_until(
        lambda: _find_session(ssm, "History", session_id),
        lambda s: s is not None,
        timeout_s=120,
        interval_s=5,
    )
    assert history is not None, "terminated session never appeared in DescribeSessions History"
    assert history["Status"] == "Terminated", f"expected Terminated, got {history['Status']}"


def _best_effort_terminate(ssm, session_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        ssm.terminate_session(SessionId=session_id)
    except ClientError as err:
        # A session the service does not know, or one already terminated, needs no teardown.
        error = err.response["Error"]
        terminated = "Session is not in a valid state" in error.get("Message", "")
        if error["Code"] == "ValidationException" and terminated:
            return
        if error["Code"] != "DoesNotExistException":
            raise


def _find_session(ssm, state: str, session_id: str):
    resp = ssm.describe_sessions(
        State=state, Filters=[{"key": "SessionId", "value": session_id}]
    )
    for session in resp.get("Sessions", []):
        if session["SessionId"] == session_id:
            return session
    return None


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        if predicate(value):
            return value
        time.sleep(interval_s)
        value = probe()
    if predicate(value):
        return value
    raise AssertionError(f"_poll_until timed out after {timeout_s}s, last value: {value!r}")


# ===== helpers =====
def _default_subnet_id(ec2, *, ctx):
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        return None
    subnets = ec2.describe_subnets(
        Filters=[
            {"Name": "vpc-id", "Values": [vpcs[0]["VpcId"]]},
            {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ]
    )["Subnets"]
    return subnets[0]["SubnetId"] if subnets else None


def _provision_connected_target(ctx) -> str:
    """Create an IAM role + instance profile with AmazonSSMManagedInstanceCore, launch an
    EC2 instance, and wait until it registers Online with Systems Manager. Returns InstanceId."""
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    subnet_id = _default_subnet_id(ec2, ctx=ctx)
    if not subnet_id:
        raise AssertionError(
            "no default VPC/subnet available to launch a test managed-instance EC2 host"
        )

    role_name = ctx.unique_name("sim2real-ssm-role-")
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

    profile_name = ctx.unique_name("sim2real-ssm-profile-")
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=profile_name, RoleName=role_name
        )
    )

    ami_id = ssm.get_parameter(Name=_AMI_PARAM)["Parameter"]["Value"]
    name_tag = ctx.unique_name("sim2real-ssm-target-")

    instance_id = None
    last_err = None
    deadline = time.monotonic() + 90
    while instance_id is None and time.monotonic() < deadline:
        try:
            run_resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                SubnetId=subnet_id,
                IamInstanceProfile={"Name": profile_name},
                TagSpecifications=[
                    {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name_tag}]}
                ],
            )
            instance_id = run_resp["Instances"][0]["InstanceId"]
        except ClientError as exc:
            last_err = exc
            # IAM instance-profile propagation to EC2 can lag briefly after creation.
            if exc.response["Error"]["Code"] not in (
                "InvalidParameterValue",
                "InvalidParameterValueError",
            ):
                raise
            time.sleep(5)
    if instance_id is None:
        raise AssertionError(f"run_instances never succeeded after IAM propagation: {last_err}")
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))

    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        info = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )["InstanceInformationList"]
        if info and info[0].get("PingStatus") == "Online":
            return instance_id
        time.sleep(2)
    raise AssertionError(f"instance {instance_id} never reached SSM PingStatus=Online in time")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
