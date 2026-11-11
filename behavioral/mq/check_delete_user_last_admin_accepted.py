"""delete-user-last-admin-accepted."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-user-last-admin-accepted"
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


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteUser on a broker's only ActiveMQ user is accepted and staged as a pending DELETE, and
    RebootBroker applies it: the broker returns to RUNNING and DescribeUser fails with
    NotFoundException.
    """
    mq = ctx.client("mq")
    subnet_id = _default_subnet(ctx)
    broker_name = ctx.unique_name("sim2real-mqbroker-")
    sole_user = ctx.unique_name("mqsole-")
    password = "Sim2Real-Str0ngPwd-2024"

    created = mq.create_broker(
        BrokerName=broker_name,
        DeploymentMode="SINGLE_INSTANCE",
        EngineType="ACTIVEMQ",
        HostInstanceType="mq.t3.micro",
        PubliclyAccessible=False,
        SubnetIds=[subnet_id],
        SecurityGroups=[ctx.network().security_group_id],
        Users=[{"Username": sole_user, "Password": password}],
        Tags={"sim2real-check": CHECK},
    )
    broker_id = created["BrokerId"]
    ctx.on_cleanup(lambda: mq.delete_broker(BrokerId=broker_id))

    _wait_broker_state(mq, broker_id, "RUNNING")

    # DeleteUser on the sole remaining user is accepted -- AWS does not block it here.
    mq.delete_user(BrokerId=broker_id, Username=sole_user)

    # independent read: the delete is staged, not yet applied -- the user still describes,
    # now carrying a pending DELETE (the same async-apply model CreateUser uses).
    staged = mq.describe_user(BrokerId=broker_id, Username=sole_user)
    assert staged.get("Pending", {}).get("PendingChange") == "DELETE", staged

    # RebootBroker applies the pending delete, even though it leaves zero users configured,
    # and the broker still comes back to RUNNING.
    mq.reboot_broker(BrokerId=broker_id)
    _wait_broker_state(mq, broker_id, "RUNNING")

    # terminal, independent read through a different operation than either mutation: the
    # user is actually gone once the reboot lands.
    gone_code, gone_message = _error(lambda: mq.describe_user(BrokerId=broker_id, Username=sole_user))
    assert gone_code == "NotFoundException", gone_code
    expected = f"Can\u2019t find user [{sole_user}] for broker [{broker_id}]. Make sure user exists."
    assert gone_message == expected, gone_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
