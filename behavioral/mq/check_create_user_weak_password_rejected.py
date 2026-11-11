"""create-user-weak-password-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-user-weak-password-rejected"
GROUP = "overly-permissive"
SERVICES = ["mq"]


def _default_subnet(ctx) -> str:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to provision a subnet for the broker")
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpcs[0]["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets available for the broker")
    return subnets[0]["SubnetId"]


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _wait_broker_state(mq, broker_id, target_state, timeout_s=1200.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = mq.describe_broker(BrokerId=broker_id)["BrokerState"]
        if last == target_state:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"broker never reached {target_state}; last observed state={last}")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateUser rejects a password with fewer than 4 unique characters (BadRequestException), never creating the user."""
    mq = ctx.client("mq")
    subnet_id = _default_subnet(ctx)
    broker_name = ctx.unique_name("sim2real-mqbroker-")
    admin_user = ctx.unique_name("mqadmin-")
    admin_password = "Sim2Real-Str0ngPwd-2024"

    created = mq.create_broker(
        BrokerName=broker_name,
        DeploymentMode="SINGLE_INSTANCE",
        EngineType="ACTIVEMQ",
        HostInstanceType="mq.t3.micro",
        PubliclyAccessible=False,
        SubnetIds=[subnet_id],
        SecurityGroups=[ctx.network().security_group_id],
        Users=[{"Username": admin_user, "Password": admin_password}],
    )
    broker_id = created["BrokerId"]
    ctx.on_cleanup(lambda: mq.delete_broker(BrokerId=broker_id))

    _wait_broker_state(mq, broker_id, "RUNNING")

    weak_user = ctx.unique_name("mqweak-")
    weak_password = "aaaaaaaaaaaa"  # 12 chars but only 1 unique char -> violates the 4-unique-char rule
    code, message = _error(lambda: mq.create_user(BrokerId=broker_id, Username=weak_user, Password=weak_password))
    assert code == "BadRequestException", code
    assert message == "Password must contain at least [4] unique characters.", message

    # effect absent: the user was never created.
    not_found_code, not_found_message = _error(lambda: mq.describe_user(BrokerId=broker_id, Username=weak_user))
    assert not_found_code == "NotFoundException", not_found_code
    expected = f"Can\u2019t find user [{weak_user}] for broker [{broker_id}]. Make sure user exists."
    assert not_found_message == expected, not_found_message

    # positive control: a compliant password succeeds.
    strong_user = ctx.unique_name("mqstrong-")
    mq.create_user(BrokerId=broker_id, Username=strong_user, Password="Compliant-Str0ngPwd-2024")
    described = mq.describe_user(BrokerId=broker_id, Username=strong_user)
    assert described["Username"] == strong_user, f"expected user {strong_user!r}, got {described.get('Username')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
