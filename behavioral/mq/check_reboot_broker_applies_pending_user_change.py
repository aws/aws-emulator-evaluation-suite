"""reboot-broker-applies-pending-user-change."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "reboot-broker-applies-pending-user-change"
GROUP = "state"
SERVICES = ["mq"]


def _default_subnet(ctx) -> str:
    # The default VPC and its default-for-az subnets are the account baseline.
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    assert vpcs, "the account baseline's shared network is missing"
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    assert subnets, f"the account baseline's network subnets are missing from {vpc_id}"
    return subnets[0]["SubnetId"]


def _wait_broker_state(mq, broker_id, target_state, timeout_s=1200.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = mq.describe_broker(BrokerId=broker_id)["BrokerState"]
        if last == target_state:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"broker never reached {target_state}; last observed state={last}")


def _wait_no_pending_change(mq, broker_id, username, timeout_s=1200.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    last_pending = "unknown"
    while time.monotonic() < deadline:
        described = mq.describe_user(BrokerId=broker_id, Username=username)
        last_pending = described.get("Pending")
        if last_pending is None:
            return
        time.sleep(interval_s)
    raise AssertionError(f"user pending change never cleared; last Pending={last_pending}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateUser is 'pending' until RebootBroker applies it, matching MQ's async-apply model."""
    mq = ctx.client("mq")
    subnet_id = _default_subnet(ctx)
    broker_name = ctx.unique_name("sim2real-mqbroker-")
    admin_user = ctx.unique_name("mqadmin-")
    password = "Sim2Real-Str0ngPwd-2024"

    created = mq.create_broker(
        BrokerName=broker_name,
        DeploymentMode="SINGLE_INSTANCE",
        EngineType="ACTIVEMQ",
        HostInstanceType="mq.t3.micro",
        PubliclyAccessible=False,
        SubnetIds=[subnet_id],
        SecurityGroups=[ctx.network().security_group_id],
        Users=[{"Username": admin_user, "Password": password}],
        Tags={"sim2real": CHECK},
    )
    broker_id = created["BrokerId"]
    ctx.on_cleanup(lambda: mq.delete_broker(BrokerId=broker_id))

    _wait_broker_state(mq, broker_id, "RUNNING")

    new_user = ctx.unique_name("mquser-")
    mq.create_user(BrokerId=broker_id, Username=new_user, Password="Another-Str0ngPwd-2024")

    described_before = mq.describe_user(BrokerId=broker_id, Username=new_user)
    assert described_before["Pending"]["PendingChange"] == "CREATE", described_before

    mq.reboot_broker(BrokerId=broker_id)
    _wait_broker_state(mq, broker_id, "RUNNING")

    _wait_no_pending_change(mq, broker_id, new_user)
    described_after = mq.describe_user(BrokerId=broker_id, Username=new_user)
    assert described_after.get("Pending") is None, described_after


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
