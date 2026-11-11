"""instance-create-active-attributes-tags-delete."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "instance-create-active-attributes-tags-delete"
GROUP = "instance-lifecycle"
SERVICES = ["connect"]


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


def _list_all_aliases(connect):
    aliases = set()
    next_token = None
    while True:
        kwargs = {"MaxResults": 10}
        if next_token:
            kwargs["NextToken"] = next_token
        page = connect.list_instances(**kwargs)
        aliases.update(s["InstanceAlias"] for s in page["InstanceSummaryList"])
        next_token = page.get("NextToken")
        if not next_token:
            break
    return aliases


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateInstance converges to ACTIVE with the fields it was given, a tag and an
    attribute round-trip through it, and DeleteInstance converges to a terminal state
    where the instance is absent from both DescribeInstance and ListInstances.
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
        Tags={"sim2real": "instance-lifecycle"},
    )
    instance_id = created["Id"]
    instance_arn = created["Arn"]
    ctx.on_cleanup(
        _teardown(
            lambda: connect.delete_instance(InstanceId=instance_id),
            "ResourceNotFoundException",
        )
    )

    active = _poll_until_active(connect, instance_id)
    assert active["InstanceAlias"] == alias, (
        f"expected alias {alias!r}, got {active['InstanceAlias']!r}"
    )
    assert active["IdentityManagementType"] == "CONNECT_MANAGED", (
        f"expected CONNECT_MANAGED, got {active['IdentityManagementType']!r}"
    )
    assert active["InboundCallsEnabled"] is True, (
        f"expected InboundCallsEnabled True, got {active!r}"
    )
    assert active["OutboundCallsEnabled"] is False, (
        f"expected OutboundCallsEnabled False, got {active!r}"
    )

    initial_tags = connect.list_tags_for_resource(resourceArn=instance_arn)["tags"]
    assert initial_tags.get("sim2real") == "instance-lifecycle", (
        f"CreateInstance's own Tags did not round-trip, got {initial_tags!r}"
    )

    connect.tag_resource(resourceArn=instance_arn, tags={"sim2real-phase": "active"})
    tagged = connect.list_tags_for_resource(resourceArn=instance_arn)["tags"]
    assert tagged.get("sim2real-phase") == "active", (
        f"TagResource did not take, tags are {tagged!r}"
    )

    connect.untag_resource(resourceArn=instance_arn, tagKeys=["sim2real-phase"])
    untagged = connect.list_tags_for_resource(resourceArn=instance_arn)["tags"]
    assert "sim2real-phase" not in untagged, f"UntagResource left the key behind: {untagged!r}"
    assert untagged.get("sim2real") == "instance-lifecycle", (
        f"UntagResource removed an unrelated key too: {untagged!r}"
    )

    connect.update_instance_attribute(
        InstanceId=instance_id, AttributeType="CONTACTFLOW_LOGS", Value="true"
    )
    on = connect.describe_instance_attribute(
        InstanceId=instance_id, AttributeType="CONTACTFLOW_LOGS"
    )["Attribute"]
    assert on["Value"] == "true", f"expected CONTACTFLOW_LOGS 'true', got {on!r}"

    connect.update_instance_attribute(
        InstanceId=instance_id, AttributeType="CONTACTFLOW_LOGS", Value="false"
    )
    off = connect.describe_instance_attribute(
        InstanceId=instance_id, AttributeType="CONTACTFLOW_LOGS"
    )["Attribute"]
    assert off["Value"] == "false", (
        f"expected CONTACTFLOW_LOGS 'false' after the update, got {off!r}"
    )

    listed = {}
    next_token = None
    while True:
        kwargs = {"InstanceId": instance_id}
        if next_token:
            kwargs["NextToken"] = next_token
        page = connect.list_instance_attributes(**kwargs)
        listed.update({a["AttributeType"]: a["Value"] for a in page["Attributes"]})
        next_token = page.get("NextToken")
        if not next_token:
            break
    assert listed.get("CONTACTFLOW_LOGS") == "false", (
        f"ListInstanceAttributes gave {listed!r}, expected CONTACTFLOW_LOGS false"
    )

    inbound = connect.describe_instance_attribute(
        InstanceId=instance_id, AttributeType="INBOUND_CALLS"
    )["Attribute"]
    assert inbound["Value"] == "true", (
        f"expected INBOUND_CALLS 'true' from CreateInstance, got {inbound!r}"
    )
    outbound = connect.describe_instance_attribute(
        InstanceId=instance_id, AttributeType="OUTBOUND_CALLS"
    )["Attribute"]
    assert outbound["Value"] == "false", (
        f"expected OUTBOUND_CALLS 'false' from CreateInstance, got {outbound!r}"
    )

    connect.delete_instance(InstanceId=instance_id)
    _poll_until_gone(connect, instance_id)

    aliases_after = _list_all_aliases(connect)
    assert alias not in aliases_after, f"ListInstances still shows deleted alias {alias!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
