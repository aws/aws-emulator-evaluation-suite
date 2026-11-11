"""start-session-target-not-connected-rejected."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "start-session-target-not-connected-rejected"
GROUP = "error-semantics"
SERVICES = ["ssm"]

_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_SSM_CORE_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartSession on a managed-node id whose agent never connected fails with TargetNotConnected "<id> is not
    connected." and creates no session, while the same call on a connected node succeeds."""
    ssm = ctx.client("ssm")

    # Positive control: a genuinely connected managed node accepts StartSession.
    instance_id = _provision_connected_target(ctx)
    control_resp = ssm.start_session(Target=instance_id)
    control_session_id = control_resp["SessionId"]
    ctx.on_cleanup(lambda: _terminate(ssm, control_session_id))

    # Break exactly one thing: a syntactically valid managed-node id that never registered.
    bogus_target = "i-" + uuid.uuid4().hex[:17]
    code, message = _error_code(
        lambda: ssm.start_session(Target=bogus_target),
        on_unexpected_success=lambda resp: ctx.on_cleanup(
            lambda: _terminate(ssm, resp["SessionId"])
        ),
    )
    assert code == "TargetNotConnected", f"expected TargetNotConnected, got {code!r}"
    assert message == f"{bogus_target} is not connected.", f"StartSession message: {message!r}"

    # Effect absent: no session was created for the bogus target in either state.
    for state in ("Active", "History"):
        sessions = ssm.describe_sessions(
            State=state, Filters=[{"key": "Target", "value": bogus_target}]
        )["Sessions"]
        assert not sessions, f"rejected StartSession left a {state} session behind: {sessions}"


def _terminate(ssm, session_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        ssm.terminate_session(SessionId=session_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "DoesNotExistException":
            raise


def _error_code(fn, *, on_unexpected_success=None):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises, because
    accepting a target that never connected must fail loudly, not as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    if on_unexpected_success is not None:
        on_unexpected_success(result)
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _provision_connected_target(ctx) -> str:
    """Create an IAM role + instance profile with AmazonSSMManagedInstanceCore, launch an
    EC2 instance, and wait until it registers Online with Systems Manager. Returns InstanceId."""
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

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
                IamInstanceProfile={"Name": profile_name},
                TagSpecifications=[
                    {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name_tag}]}
                ],
                SubnetId=ctx.network().subnet_ids[0],
            )
            instance_id = run_resp["Instances"][0]["InstanceId"]
        except ClientError as exc:
            last_err = exc
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
