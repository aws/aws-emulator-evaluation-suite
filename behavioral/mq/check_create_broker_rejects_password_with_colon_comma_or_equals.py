"""create-broker-rejects-password-with-colon-comma-or-equals."""

from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-broker-rejects-password-with-colon-comma-or-equals"
GROUP = "overly-permissive"
SERVICES = ["mq"]

_INVALID_PASSWORD = (
    "BadRequestException",
    "Make sure your password doesn't contain invalid characters [, :=].",
)


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, got_code
    assert got_message == message, got_message


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_broker_state(ctx, mq, broker_id, target_state, timeout_s=1200.0, interval_s=20.0):
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = mq.describe_broker(BrokerId=broker_id)["BrokerState"]
        if last == target_state:
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(
            f"broker {broker_id} reaching {target_state}: the run budget ended first; not graded"
        )
    raise AssertionError(f"broker never reached {target_state}; last observed state={last}")


def _all_broker_names(mq) -> set[str]:
    names: set[str] = set()
    for page in mq.get_paginator("list_brokers").paginate():
        names.update(s["BrokerName"] for s in page["BrokerSummaries"])
    return names


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """CreateBroker rejects an ActiveMQ admin password containing ':', ',' or '=' with
    BadRequestException "Make sure your password doesn't contain invalid characters [, :=]." and
    mints no broker; a password without them is accepted and DescribeBroker lists its one user."""
    mq = ctx.client("mq")
    subnet_id = ctx.network().subnet_ids[0]

    rejected_names = []
    for bad_char in (":", ",", "="):
        broker_name = ctx.unique_name("sim2real-mqbadpwd-")
        username = ctx.unique_name("mqadmin-")
        password = f"Sim2Real{bad_char}StrongPwd2024"
        # An unexpected success still creates a broker: its delete is registered before the call.
        accepted = {}
        ctx.on_cleanup(
            lambda accepted=accepted: (
                mq.delete_broker(BrokerId=accepted["BrokerId"])
                if accepted.get("BrokerId")
                else None
            )
        )

        def create(
            broker_name=broker_name, username=username, password=password, accepted=accepted
        ):
            accepted.update(
                mq.create_broker(
                    BrokerName=broker_name,
                    DeploymentMode="SINGLE_INSTANCE",
                    EngineType="ACTIVEMQ",
                    HostInstanceType="mq.t3.micro",
                    PubliclyAccessible=False,
                    SubnetIds=[subnet_id],
                    SecurityGroups=[ctx.network().security_group_id],
                    Users=[{"Username": username, "Password": password}],
                )
            )
            return accepted

        expect_error(create, *_INVALID_PASSWORD)
        rejected_names.append(broker_name)

    # effect absent: none of the three rejected CreateBroker calls minted a broker.
    existing = _all_broker_names(mq)
    for name in rejected_names:
        assert name not in existing, f"rejected CreateBroker for {name!r} minted a broker anyway"

    # positive control: the same shape of password, without the invalid characters, is accepted.
    good_name = ctx.unique_name("sim2real-mqgoodpwd-")
    good_user = ctx.unique_name("mqadmin-")
    good_password = "Sim2Real-StrongPwd-2024"
    created = mq.create_broker(
        BrokerName=good_name,
        DeploymentMode="SINGLE_INSTANCE",
        EngineType="ACTIVEMQ",
        HostInstanceType="mq.t3.micro",
        PubliclyAccessible=False,
        SubnetIds=[subnet_id],
        SecurityGroups=[ctx.network().security_group_id],
        Users=[{"Username": good_user, "Password": good_password}],
    )
    broker_id = created["BrokerId"]
    ctx.on_cleanup(lambda: mq.delete_broker(BrokerId=broker_id))
    want_arn = (
        f"arn:{mq.meta.partition}:mq:{ctx.region}:{ctx.account}:broker:{good_name}:{broker_id}"
    )
    assert created["BrokerArn"] == want_arn, (
        f"CreateBroker returned BrokerArn {created['BrokerArn']!r}, expected {want_arn!r}"
    )

    _wait_broker_state(ctx, mq, broker_id, "RUNNING")
    described = mq.describe_broker(BrokerId=broker_id)
    usernames = [u["Username"] for u in described["Users"]]
    assert usernames == [good_user], f"expected the accepted user {good_user!r}, got {usernames!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
