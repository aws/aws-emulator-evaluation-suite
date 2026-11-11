"""deploy-logs-1-kms-log-group."""
from __future__ import annotations

import json
import sys
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-logs-1-kms-log-group"
GROUP = "deploy-kms-log-group"
SERVICES = ["logs"]

_STACK_TERMINAL = {
    "CREATE_COMPLETE",
    "CREATE_FAILED",
    "ROLLBACK_COMPLETE",
    "ROLLBACK_FAILED",
    "UPDATE_COMPLETE",
    "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_ROLLBACK_FAILED",
    "UPDATE_FAILED",
    "DELETE_COMPLETE",
    "DELETE_FAILED",
}


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:data-plane",
    "concern:deploy",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A CloudFormation-deployed CMK-encrypted log group round-trips events; a key policy without
    the Logs grant fails the group and rolls back; dropping KmsKeyId updates in place and keeps
    the events; deleting the stack removes the group and schedules the key for deletion.
    """
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")
    kms = ctx.client("kms")

    # Stack A: the key policy grants CloudWatch Logs.
    group_a = ctx.unique_name("sim2real-behav-logs-kmsdep-a-")
    stream_a = ctx.unique_name("sim2real-behav-logs-kmsdep-sa-")
    stack_a = ctx.unique_name("sim2real-behav-logs-kmsdep-a-")
    keys_a: set[str] = set()

    created_a = cfn.create_stack(
        StackName=stack_a,
        TemplateBody=json.dumps(_template(group_a, stream_a, grant_logs=True, encrypt=True)),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _teardown_stack(cfn, kms, created_a["StackId"], keys_a))
    stack_a_id = created_a["StackId"]

    status_a = _wait_stack(cfn, stack_a_id)
    assert status_a == "CREATE_COMPLETE", (
        f"stack A (key policy grants logs) ended {status_a!r}, expected 'CREATE_COMPLETE'; "
        f"failures: {_failed_events(cfn, stack_a_id)!r}"
    )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in
               cfn.describe_stacks(StackName=stack_a_id)["Stacks"][0].get("Outputs", [])}
    key_arn = outputs.get("KeyArn")
    assert key_arn and key_arn.startswith("arn:"), f"stack A KeyArn output was {key_arn!r}"
    keys_a.add(key_arn)

    phys_before = _physical_id(cfn, stack_a_id, "LogGroup")
    assert phys_before == group_a, (
        f"LogGroup physical id {phys_before!r} is not the declared LogGroupName {group_a!r}"
    )

    lg = _describe_group(logs, group_a)
    assert lg is not None, f"log group {group_a!r} from CREATE_COMPLETE stack A is not described"
    assert lg.get("kmsKeyId") == key_arn, (
        f"describe_log_groups kmsKeyId={lg.get('kmsKeyId')!r}, expected the stack's key {key_arn!r}"
    )
    assert lg.get("retentionInDays") == 3, (
        f"describe_log_groups retentionInDays={lg.get('retentionInDays')!r}, expected 3"
    )
    created_at = lg.get("creationTime")
    assert isinstance(created_at, int), f"creationTime was {created_at!r}"

    base_ts = int(time.time() * 1000)
    payload = [
        "kms-encrypted line one",
        '{"level":"INFO","msg":"json body \\u00e9 survives"}',
        "tabs\tand  spaces   are\tkept",
    ]
    sent = [{"timestamp": base_ts + i, "message": m} for i, m in enumerate(payload)]
    put = logs.put_log_events(logGroupName=group_a, logStreamName=stream_a, logEvents=sent)
    assert "rejectedLogEventsInfo" not in put, (
        f"encrypted group rejected events: {put.get('rejectedLogEventsInfo')!r}"
    )
    got = _read_events(logs, group_a, stream_a, expected=len(sent))
    assert got == [(e["timestamp"], e["message"]) for e in sent], (
        f"get_log_events on the CMK-encrypted group returned {got!r}, expected {sent!r}"
    )

    # Stack B: the key policy omits the Logs grant.
    group_b = ctx.unique_name("sim2real-behav-logs-kmsdep-b-")
    stream_b = ctx.unique_name("sim2real-behav-logs-kmsdep-sb-")
    stack_b = ctx.unique_name("sim2real-behav-logs-kmsdep-b-")
    keys_b: set[str] = set()

    created_b = cfn.create_stack(
        StackName=stack_b,
        TemplateBody=json.dumps(_template(group_b, stream_b, grant_logs=False, encrypt=True)),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _teardown_stack(cfn, kms, created_b["StackId"], keys_b))
    stack_b_id = created_b["StackId"]

    status_b = _wait_stack(cfn, stack_b_id)
    keys_b.update(_resource_ids_from_events(cfn, stack_b_id, "AWS::KMS::Key"))
    assert status_b == "ROLLBACK_COMPLETE", (
        f"stack B (key policy omits the logs grant) ended {status_b!r}, expected 'ROLLBACK_COMPLETE'"
    )
    statuses_b = _resource_statuses(cfn, stack_b_id)
    assert "CREATE_FAILED" in statuses_b.get("LogGroup", []), (
        f"stack B LogGroup never reported CREATE_FAILED; per-resource statuses {statuses_b!r}"
    )
    # CloudFormation starts the dependent LogGroup once the Key reports CONFIGURATION_COMPLETE; the
    # LogGroup failure can then cancel the Key's eventual-consistency check before CREATE_COMPLETE.
    key_configured = any(
        e["ResourceStatus"] == "CREATE_COMPLETE" or e.get("DetailedStatus") == "CONFIGURATION_COMPLETE"
        for e in _stack_events(cfn, stack_b_id) if e["LogicalResourceId"] == "Key")
    assert key_configured, (
        f"stack B's KMS key itself should have been created (only the grant is missing); "
        f"per-resource statuses {statuses_b!r}"
    )
    assert "CREATE_COMPLETE" not in statuses_b.get("LogStream", []), (
        f"stack B LogStream reached CREATE_COMPLETE without its group: {statuses_b!r}"
    )
    assert _describe_group(logs, group_b) is None, (
        f"log group {group_b!r} exists although its stack rolled back"
    )

    # Removing KmsKeyId is an update with no interruption: same group, same events.
    cfn.update_stack(
        StackName=stack_a_id,
        TemplateBody=json.dumps(_template(group_a, stream_a, grant_logs=True, encrypt=False)),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    status_upd = _wait_stack(cfn, stack_a_id)
    assert status_upd == "UPDATE_COMPLETE", (
        f"update removing KmsKeyId ended {status_upd!r}, expected 'UPDATE_COMPLETE'; "
        f"failures: {_failed_events(cfn, stack_a_id)!r}"
    )
    phys_after = _physical_id(cfn, stack_a_id, "LogGroup")
    assert phys_after == phys_before, (
        f"LogGroup physical id changed across the update {phys_before!r} -> {phys_after!r}: "
        f"replaced, not updated in place"
    )
    lg_after = _poll_group(logs, group_a, lambda g: "kmsKeyId" not in g)
    assert "kmsKeyId" not in lg_after, (
        f"kmsKeyId still {lg_after.get('kmsKeyId')!r} after the template dropped it"
    )
    assert lg_after.get("creationTime") == created_at, (
        f"creationTime moved {created_at!r} -> {lg_after.get('creationTime')!r}: "
        f"the group was recreated, not updated in place"
    )
    assert lg_after.get("retentionInDays") == 3, (
        f"retentionInDays drifted to {lg_after.get('retentionInDays')!r} across the update"
    )
    got_after = _read_events(logs, group_a, stream_a, expected=len(sent))
    assert got_after == got, (
        f"events written under the CMK changed after disassociation: {got_after!r} vs {got!r}"
    )

    cfn.delete_stack(StackName=stack_a_id)
    status_del = _wait_stack(cfn, stack_a_id)
    assert status_del == "DELETE_COMPLETE", f"stack A delete ended {status_del!r}"
    assert _describe_group(logs, group_a) is None, (
        f"log group {group_a!r} still described after its stack was deleted"
    )
    gone_code, gone_message = _error(lambda: logs.put_log_events(
        logGroupName=group_a, logStreamName=stream_a,
        logEvents=[{"timestamp": int(time.time() * 1000), "message": "after delete"}]))
    assert gone_code == "ResourceNotFoundException", (
        f"put_log_events to the deleted group returned {gone_code!r}, expected ResourceNotFoundException"
    )
    assert gone_message == "The specified log group does not exist.", (
        f"put_log_events to the deleted group returned message {gone_message!r}"
    )
    key_state = kms.describe_key(KeyId=key_arn)["KeyMetadata"]["KeyState"]
    assert key_state == "PendingDeletion", (
        f"stack A's CMK is {key_state!r} after stack deletion, expected 'PendingDeletion'"
    )


def _template(group: str, stream: str, *, grant_logs: bool, encrypt: bool) -> dict:
    statements: list[dict] = [{
        "Sid": "AccountRootAdmin",
        "Effect": "Allow",
        "Principal": {"AWS": {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"}},
        "Action": "kms:*",
        "Resource": "*",
    }]
    if grant_logs:
        statements.append({
            "Sid": "AllowCloudWatchLogsForThisGroup",
            "Effect": "Allow",
            "Principal": {"Service": {"Fn::Sub": "logs.${AWS::Region}.amazonaws.com"}},
            "Action": ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*",
                       "kms:GenerateDataKey*", "kms:Describe*"],
            "Resource": "*",
            "Condition": {"ArnEquals": {"kms:EncryptionContext:aws:logs:arn": {
                "Fn::Sub": "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:"
                           + group}}},
        })
    group_props: dict = {
        "LogGroupName": group,
        "RetentionInDays": 3,
        "Tags": [{"Key": "sim2real", "Value": CHECK}],
    }
    if encrypt:
        group_props["KmsKeyId"] = {"Fn::GetAtt": ["Key", "Arn"]}
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Key": {
                "Type": "AWS::KMS::Key",
                "Properties": {
                    "Description": f"sim2real {CHECK} {group}",
                    "PendingWindowInDays": 7,
                    "KeyPolicy": {"Version": "2012-10-17", "Statement": statements},
                    "Tags": [{"Key": "sim2real", "Value": CHECK}],
                },
            },
            "LogGroup": {"Type": "AWS::Logs::LogGroup", "Properties": group_props},
            "LogStream": {
                "Type": "AWS::Logs::LogStream",
                "Properties": {"LogGroupName": {"Ref": "LogGroup"}, "LogStreamName": stream},
            },
        },
        "Outputs": {"KeyArn": {"Value": {"Fn::GetAtt": ["Key", "Arn"]}}},
    }


def _wait_stack(cfn: Any, stack_id: str, timeout_s: float = 900.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = "UNKNOWN"
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in _STACK_TERMINAL:
            return status
        time.sleep(2)
    raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s}s")


def _stack_events(cfn: Any, stack_id: str) -> list[dict]:
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return events


def _resource_statuses(cfn: Any, stack_id: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for e in reversed(_stack_events(cfn, stack_id)):
        out.setdefault(e["LogicalResourceId"], []).append(e["ResourceStatus"])
    return out


def _failed_events(cfn: Any, stack_id: str) -> list[tuple]:
    return [(e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
            for e in _stack_events(cfn, stack_id) if e["ResourceStatus"].endswith("FAILED")]


def _resource_ids_from_events(cfn: Any, stack_id: str, rtype: str) -> set[str]:
    return {e["PhysicalResourceId"] for e in _stack_events(cfn, stack_id)
            if e.get("ResourceType") == rtype and e.get("PhysicalResourceId")}


def _physical_id(cfn: Any, stack_id: str, logical: str) -> str:
    return cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId=logical)[
        "StackResourceDetail"]["PhysicalResourceId"]


def _describe_group(logs: Any, name: str) -> dict | None:
    for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=name):
        for g in page["logGroups"]:
            if g["logGroupName"] == name:
                return g
    return None


def _poll_group(logs: Any, name: str, cond, timeout_s: float = 60.0) -> dict:
    deadline = time.monotonic() + timeout_s
    g = _describe_group(logs, name)
    while time.monotonic() < deadline:
        g = _describe_group(logs, name)
        assert g is not None, f"log group {name!r} disappeared"
        if cond(g):
            return g
        time.sleep(3)
    return g


def _read_events(logs: Any, group: str, stream: str, expected: int,
                 timeout_s: float = 60.0) -> list[tuple[int, str]]:
    deadline = time.monotonic() + timeout_s
    got: list[tuple[int, str]] = []
    while time.monotonic() < deadline:
        resp = logs.get_log_events(logGroupName=group, logStreamName=stream, startFromHead=True)
        got = [(e["timestamp"], e["message"]) for e in resp["events"]]
        if len(got) >= expected:
            return got
        time.sleep(2)
    raise AssertionError(f"{group}/{stream} held {len(got)} of {expected} events: {got!r}")


def _error(fn: Any) -> tuple[str, str | None]:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded and returned {result!r}")


def _teardown_stack(cfn: Any, kms: Any, stack_id: str, known_keys: set[str]) -> None:
    """Delete the stack, then make sure every CMK it ever created is PendingDeletion;
    any failure raises."""
    problems: list[str] = []
    keys = set(known_keys)
    try:
        keys |= _resource_ids_from_events(cfn, stack_id, "AWS::KMS::Key")
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status != "DELETE_COMPLETE":
            cfn.delete_stack(StackName=stack_id)
            status = _wait_stack(cfn, stack_id, timeout_s=600.0)
        if status != "DELETE_COMPLETE":
            problems.append(f"stack {stack_id} ended {status!r}, not DELETE_COMPLETE")
    finally:
        for key in sorted(keys):
            state = kms.describe_key(KeyId=key)["KeyMetadata"]["KeyState"]
            if state != "PendingDeletion":
                kms.schedule_key_deletion(KeyId=key, PendingWindowInDays=7)
    if problems:
        raise RuntimeError(f"{CHECK}: " + "; ".join(problems))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
