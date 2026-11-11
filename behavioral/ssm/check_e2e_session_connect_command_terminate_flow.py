"""e2e-session-connect-command-terminate-flow."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-session-connect-command-terminate-flow"
GROUP = "state-machine"
SERVICES = ["ssm"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Starting a session makes the target show as connected and the session Active in
    DescribeSessions; terminating it flips the session to History and removes it from the
    Active listing -- the end-state consequence of the full connect/terminate flow."""
    ssm = ctx.client("ssm")
    instance_id = _provision_ssm_managed_instance(ctx)

    status = ssm.get_connection_status(Target=instance_id)["Status"]
    assert status == "connected", f"expected managed instance to be connected, got {status!r}"

    started = ssm.start_session(Target=instance_id)
    session_id = started["SessionId"]

    def _active_sessions():
        resp = ssm.describe_sessions(
            State="Active", Filters=[{"key": "SessionId", "value": session_id}]
        )
        return resp.get("Sessions", [])

    active = _poll_until(
        _active_sessions, lambda sessions: bool(sessions), timeout_s=60, interval_s=3
    )
    assert active[0]["SessionId"] == session_id, (
        f"expected active session {session_id!r}, got {active[0]['SessionId']!r}"
    )
    assert active[0]["Target"] == instance_id, (
        f"expected active session target {instance_id!r}, got {active[0]['Target']!r}"
    )

    ssm.terminate_session(SessionId=session_id)

    _poll_until(_active_sessions, lambda sessions: len(sessions) == 0, timeout_s=60, interval_s=3)

    def _history_sessions():
        resp = ssm.describe_sessions(
            State="History", Filters=[{"key": "SessionId", "value": session_id}]
        )
        return resp.get("Sessions", [])

    history = _poll_until(
        _history_sessions, lambda sessions: bool(sessions), timeout_s=60, interval_s=3
    )
    assert history[0]["SessionId"] == session_id, (
        f"expected history session {session_id!r}, got {history[0]['SessionId']!r}"
    )
    assert history[0]["Status"] in ("Terminated", "Terminating"), (
        f"expected history status Terminated/Terminating, got {history[0]['Status']!r}"
    )


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _default_subnet_id(ec2, *, ctx) -> str | None:
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

    subnet_id = _default_subnet_id(ec2, ctx=ctx)
    if not subnet_id:
        raise AssertionError(
            "no default VPC/subnet available to launch a test managed-instance EC2 host"
        )

    instance_id = None
    deadline = time.monotonic() + 90
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                SubnetId=subnet_id,
                IamInstanceProfile={"Name": profile_name},
                TagSpecifications=[
                    {
                        "ResourceType": "instance",
                        "Tags": [
                            {"Key": "Name", "Value": ctx.unique_name("sim2real-ssm-managed-")}
                        ],
                    }
                ],
            )
            instance_id = resp["Instances"][0]["InstanceId"]
            break
        except Exception as exc:  # IAM instance-profile propagation lag
            last_error = exc
            time.sleep(5)
    if instance_id is None:
        raise AssertionError(f"could not launch instance (IAM propagation?): {last_error}")

    ctx.on_cleanup(lambda: _safe(lambda: ec2.terminate_instances(InstanceIds=[instance_id])))
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    _poll_until(
        lambda: ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        ).get("InstanceInformationList", []),
        lambda infos: bool(infos) and infos[0].get("PingStatus") == "Online",
        timeout_s=600,
        interval_s=15,
    )
    return instance_id


def _safe(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("InvalidInstanceID.NotFound", "NoSuchEntity"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
