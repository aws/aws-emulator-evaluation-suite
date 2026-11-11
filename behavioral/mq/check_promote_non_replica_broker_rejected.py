"""promote-non-replica-broker-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "promote-non-replica-broker-rejected"
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
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _wait_broker_state(mq, broker_id, target_state, timeout_s=1200.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = mq.describe_broker(BrokerId=broker_id)["BrokerState"]
        if last == target_state:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"broker never reached {target_state}; last observed state={last}")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Promote on a broker that is not part of a data-replication pair is rejected with BadRequestException."""
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

    code, message = _error(lambda: mq.promote(BrokerId=broker_id, Mode="SWITCHOVER"))
    assert code == "BadRequestException", code
    assert message == "This broker is not configured for cross Region data replication.", message

    # effect absent: broker is still plain RUNNING, not flipped into any replica role.
    state_after = mq.describe_broker(BrokerId=broker_id)["BrokerState"]
    assert state_after == "RUNNING", state_after

    # positive control: the broker is otherwise fully functional -- a normal management
    # call (CreateUser) still succeeds, proving Promote was rejected for its own reason
    # and not because the broker/API is universally broken.
    control_user = ctx.unique_name("mqcontrol-")
    mq.create_user(BrokerId=broker_id, Username=control_user, Password="Control-Str0ngPwd-2024")
    described = mq.describe_user(BrokerId=broker_id, Username=control_user)
    assert described["Username"] == control_user


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
