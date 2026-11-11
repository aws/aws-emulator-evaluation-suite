"""create-broker-lifecycle-reaches-running."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-broker-lifecycle-reaches-running"
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


def _wait_broker_state(mq, broker_id, target_state, timeout_s=1200.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = mq.describe_broker(BrokerId=broker_id)["BrokerState"]
        if last == target_state:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"broker never reached {target_state}; last observed state={last}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateBroker starts CREATION_IN_PROGRESS and eventually transitions to RUNNING."""
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
        Tags={"sim2real-check": CHECK},
    )
    broker_id = created["BrokerId"]
    ctx.on_cleanup(lambda: mq.delete_broker(BrokerId=broker_id))

    initial_state = mq.describe_broker(BrokerId=broker_id)["BrokerState"]
    assert initial_state == "CREATION_IN_PROGRESS", initial_state

    final_state = _wait_broker_state(mq, broker_id, "RUNNING")
    assert final_state == "RUNNING", f"expected RUNNING, got {final_state}"

    described = mq.describe_broker(BrokerId=broker_id)
    assert described["BrokerName"] == name, f"expected BrokerName={name!r}, got {described['BrokerName']!r}"
    assert described["EngineType"].upper() == "ACTIVEMQ", f"expected EngineType=ACTIVEMQ, got {described['EngineType']!r}"

    summaries = mq.list_brokers()["BrokerSummaries"]
    match = next((b for b in summaries if b["BrokerId"] == broker_id), None)
    assert match is not None, f"broker {broker_id} not found in ListBrokers summaries"
    assert match["BrokerState"] == "RUNNING", f"expected RUNNING in ListBrokers, got {match['BrokerState']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
