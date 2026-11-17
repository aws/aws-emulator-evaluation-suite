"""rabbitmq-running-broker-user-api-refused-state-unchanged."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "rabbitmq-running-broker-user-api-refused-state-unchanged"
GROUP = "negative-classes"
SERVICES = ["mq"]

_USER_API_ACTIVEMQ_ONLY = (
    "ConflictException", "The users API only applies to ActiveMQ brokers."
)


def expect_error(fn, code: str, message: str) -> None:
    """Assert ``fn()`` is refused with exactly ``code`` and ``message``; a success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        got_code = exc.response["Error"]["Code"]
        got_message = exc.response["Error"].get("Message")
        assert (got_code, got_message) == (code, message), (got_code, got_message)
        return
    raise AssertionError(f"expected ({code}, {message!r}), but the call succeeded: {result!r}")


def _poll_running(mq, broker_id, timeout_s=1800.0, interval_s=20.0) -> str:
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        state = mq.describe_broker(BrokerId=broker_id)["BrokerState"]
        if state == "RUNNING":
            return state
        time.sleep(interval_s)
    raise AssertionError(f"broker never reached RUNNING; last observed state={state!r}")


def _delete_broker_then_its_configuration(mq, broker_id, timeout_s=1800.0, interval_s=20.0):
    """Delete ``broker_id``, wait until it is gone, then delete the configuration CreateBroker
    minted for it: DeleteConfiguration refuses one still attached to a broker.
    """

    def run_undo() -> None:
        try:
            described = mq.describe_broker(BrokerId=broker_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        config_id = described["Configurations"]["Current"]["Id"]

        try:
            mq.delete_broker(BrokerId=broker_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise

        deadline = time.monotonic() + timeout_s
        while True:
            try:
                mq.describe_broker(BrokerId=broker_id)
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "NotFoundException":
                    break
                raise
            if time.monotonic() > deadline:
                raise AssertionError(f"broker {broker_id} still exists after waiting for deletion")
            time.sleep(interval_s)

        try:
            mq.delete_configuration(ConfigurationId=config_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise

    return run_undo


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """On a RUNNING RabbitMQ broker, DescribeUser, UpdateUser, DeleteUser and CreateUser are all
    refused, and DescribeBroker afterward still reports the original Users with no pending change.
    """
    mq = ctx.client("mq")
    subnet_id = ctx.network().subnet_ids[0]
    broker_name = ctx.unique_name("sim2real-mqrabbit-")
    admin_user = ctx.unique_name("sim2realadmin-")
    other_user = ctx.unique_name("sim2realother-")
    password = "Corr3ct-Horse-Battery-Staple-9"

    created = mq.create_broker(
        BrokerName=broker_name,
        DeploymentMode="SINGLE_INSTANCE",
        EngineType="RABBITMQ",
        EngineVersion="4.3",
        HostInstanceType="mq.m7g.medium",
        PubliclyAccessible=False,
        SubnetIds=[subnet_id],
        SecurityGroups=[ctx.network().security_group_id],
        Users=[{"Username": admin_user, "Password": password}],
        Tags={"sim2real": CHECK},
    )
    broker_id = created["BrokerId"]
    ctx.on_cleanup(_delete_broker_then_its_configuration(mq, broker_id))

    # A positive control: the broker genuinely reaches RUNNING with the one admin user
    # provisioned, so the refusals below are specific to the per-user API, not a dead broker.
    _poll_running(mq, broker_id)
    before = mq.describe_broker(BrokerId=broker_id)
    before_users = before["Users"]
    assert not any(u.get("PendingChange") for u in before_users), (
        f"a freshly RUNNING broker already carries a pending user change: {before_users!r}"
    )

    expect_error(
        lambda: mq.describe_user(BrokerId=broker_id, Username=admin_user), *_USER_API_ACTIVEMQ_ONLY
    )
    expect_error(
        lambda: mq.update_user(BrokerId=broker_id, Username=admin_user, ConsoleAccess=True),
        *_USER_API_ACTIVEMQ_ONLY,
    )
    expect_error(
        lambda: mq.delete_user(BrokerId=broker_id, Username=admin_user), *_USER_API_ACTIVEMQ_ONLY
    )
    expect_error(
        lambda: mq.create_user(BrokerId=broker_id, Username=other_user, Password=password),
        *_USER_API_ACTIVEMQ_ONLY,
    )

    # independent read, through DescribeBroker rather than any of the refused operations:
    # nothing was updated, deleted or scheduled, and no new user was created.
    after = mq.describe_broker(BrokerId=broker_id)
    assert after["BrokerState"] == "RUNNING", after["BrokerState"]
    assert after["Users"] == before_users, (
        f"the refused calls changed the broker's Users list from {before_users!r} to "
        f"{after['Users']!r}"
    )
    assert not any(u.get("PendingChange") for u in after["Users"]), (
        f"a pending user change appeared after the refused calls: {after['Users']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
