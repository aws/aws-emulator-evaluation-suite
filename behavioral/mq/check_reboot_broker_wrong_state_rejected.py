"""reboot-broker-wrong-state-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "reboot-broker-wrong-state-rejected"
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
    raise AssertionError(f"expected RebootBroker to be rejected, but it SUCCEEDED: {result!r}")


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
    """RebootBroker is rejected while the broker is still CREATION_IN_PROGRESS, but succeeds once RUNNING."""
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
        Tags={"sim2real-check": CHECK},
    )
    broker_id = created["BrokerId"]
    ctx.on_cleanup(lambda: mq.delete_broker(BrokerId=broker_id))

    state_now = mq.describe_broker(BrokerId=broker_id)["BrokerState"]
    assert state_now == "CREATION_IN_PROGRESS", state_now

    code, message = _error(lambda: mq.reboot_broker(BrokerId=broker_id))
    assert code == "BadRequestException", code
    assert message == f"Broker [{broker_name}] can't be restarted while in state [CREATION_IN_PROGRESS]", message

    # effect absent: reboot did not start; broker is still creating, not rebooting.
    state_after = mq.describe_broker(BrokerId=broker_id)["BrokerState"]
    assert state_after in ("CREATION_IN_PROGRESS", "RUNNING"), state_after
    assert state_after != "REBOOT_IN_PROGRESS", (
        f"reboot should not have started while broker was creating; observed state={state_after!r}"
    )

    # positive control: once RUNNING, RebootBroker is accepted and the broker returns to RUNNING.
    _wait_broker_state(mq, broker_id, "RUNNING")
    mq.reboot_broker(BrokerId=broker_id)
    final_state = _wait_broker_state(mq, broker_id, "RUNNING")
    assert final_state == "RUNNING", f"expected broker RUNNING after accepted reboot, got {final_state!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
