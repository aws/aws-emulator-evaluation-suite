"""delete-broker-removes-it."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-broker-removes-it"
GROUP = "state"
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


def _wait_deleted(mq, broker_id, timeout_s=1200.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        try:
            last_state = mq.describe_broker(BrokerId=broker_id)["BrokerState"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"broker was not deleted within {timeout_s}s; last observed state={last_state}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteBroker eventually removes the broker: DescribeBroker converges on NotFoundException,
    a mutating call on the dead id fails the same way, and the broker leaves ListBrokers."""
    mq = ctx.client("mq")
    subnet_id = _default_subnet(ctx)
    name = ctx.unique_name("sim2real-mqbroker-")
    username = ctx.unique_name("mquser-")
    password = "Sim2Real-Str0ngPwd-2024"

    created = mq.create_broker(
        BrokerName=name,
        DeploymentMode="SINGLE_INSTANCE",
        EngineType="ACTIVEMQ",
        HostInstanceType="mq.t3.micro",
        PubliclyAccessible=False,
        SubnetIds=[subnet_id],
        SecurityGroups=[ctx.network().security_group_id],
        Users=[{"Username": username, "Password": password}],
    )
    broker_id = created["BrokerId"]
    ctx.on_cleanup(lambda: mq.delete_broker(BrokerId=broker_id))

    _wait_broker_state(mq, broker_id, "RUNNING")

    mq.delete_broker(BrokerId=broker_id)
    _wait_deleted(mq, broker_id)

    summaries = mq.list_brokers()["BrokerSummaries"]
    assert all(b["BrokerId"] != broker_id for b in summaries), (
        f"deleted broker {broker_id} still present in ListBrokers: {summaries}"
    )

    reboot_code, reboot_message = _error(lambda: mq.reboot_broker(BrokerId=broker_id))
    assert reboot_code == "NotFoundException", (
        f"expected NotFoundException rebooting deleted broker {broker_id}, got {reboot_code}"
    )
    expected = (
        f"Cannot find broker ID [{broker_id}]. Verify that your broker exists or check broker permissions."
    )
    assert reboot_message == expected, reboot_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
