"""instance-deleted-id-refuses-read-and-mutation."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "instance-deleted-id-refuses-read-and-mutation"
GROUP = "instance-lifecycle"
SERVICES = ["connect"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _poll_until_active(connect, instance_id, *, budget_s=600.0, interval_s=10.0):
    """DescribeInstance until InstanceStatus leaves CREATION_IN_PROGRESS."""
    deadline = time.monotonic() + budget_s
    while True:
        instance = connect.describe_instance(InstanceId=instance_id)["Instance"]
        status = instance["InstanceStatus"]
        if status == "ACTIVE":
            return instance
        if status == "CREATION_FAILED":
            raise AssertionError(
                f"instance {instance_id} reached CREATION_FAILED: {instance.get('StatusReason')!r}"
            )
        if time.monotonic() > deadline:
            raise AssertionError(f"instance {instance_id} still {status!r} after {budget_s}s")
        time.sleep(interval_s)


def _poll_until_gone(connect, instance_id, *, budget_s=600.0, interval_s=10.0):
    """DescribeInstance until it answers ResourceNotFoundException."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            connect.describe_instance(InstanceId=instance_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() > deadline:
            raise AssertionError(f"instance {instance_id} still describable after {budget_s}s")
        time.sleep(interval_s)


def _reap_log_group(
    logs, name: str, *, reads: int = 3, interval_s: float = 5.0, budget_s: float = 180.0
) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent.

    CreateInstance provisions /aws/connect/<alias> asynchronously, and a stream flush
    can recreate it after a first delete, so one delete is not a teardown.
    """
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group {name} still present after {budget_s}s of deletes; {absent} clean reads"
                )
            time.sleep(interval_s)


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A DeleteInstance that converges leaves an id that answers ResourceNotFoundException,
    with the exact message AWS gives, to both a read and a mutation — not just one of them.
    """
    connect = ctx.client("connect")
    logs = ctx.client("logs")
    alias = ctx.unique_name("sim2real-behav-connect-")

    # Registered before create_instance so LIFO reaps the log group after the instance is gone.
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/connect/{alias}"))

    created = connect.create_instance(
        IdentityManagementType="CONNECT_MANAGED",
        InstanceAlias=alias,
        InboundCallsEnabled=True,
        OutboundCallsEnabled=False,
    )
    instance_id = created["Id"]
    ctx.on_cleanup(
        _teardown(
            lambda: connect.delete_instance(InstanceId=instance_id),
            "ResourceNotFoundException",
        )
    )

    active = _poll_until_active(connect, instance_id)
    assert active["InstanceAlias"] == alias, (
        f"positive control: expected alias {alias!r}, got {active['InstanceAlias']!r}"
    )

    # Positive control: the live id accepts the same read and mutation we will later break.
    live = connect.describe_instance(InstanceId=instance_id)["Instance"]
    assert live["Id"] == instance_id, f"positive control describe returned {live!r}"
    connect.update_instance_attribute(
        InstanceId=instance_id, AttributeType="CONTACTFLOW_LOGS", Value="true"
    )
    live_attr = connect.describe_instance_attribute(
        InstanceId=instance_id, AttributeType="CONTACTFLOW_LOGS"
    )["Attribute"]
    assert live_attr["Value"] == "true", (
        f"positive control attribute update did not take: {live_attr!r}"
    )

    connect.delete_instance(InstanceId=instance_id)
    _poll_until_gone(connect, instance_id)

    code, message = _error(lambda: connect.describe_instance(InstanceId=instance_id))
    assert code == "ResourceNotFoundException", (
        f"DescribeInstance on a deleted instance gave {code}: {message!r}"
    )
    assert message == f"Instance {instance_id} not found", (
        f"unexpected message reading a deleted instance: {message!r}"
    )

    code2, message2 = _error(
        lambda: connect.update_instance_attribute(
            InstanceId=instance_id,
            AttributeType="CONTACTFLOW_LOGS",
            Value="false",
        )
    )
    assert code2 == "ResourceNotFoundException", (
        f"UpdateInstanceAttribute on a deleted instance gave {code2}: {message2!r}"
    )
    assert message2 == f"Instance not found: {instance_id}", (
        f"unexpected message mutating a deleted instance: {message2!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
