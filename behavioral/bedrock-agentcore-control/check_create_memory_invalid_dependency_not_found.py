"""create-memory-invalid-dependency-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-memory-invalid-dependency-not-found"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateMemory whose stream delivery names a nonexistent Kinesis stream is refused with ValidationException and
    the exact stream-access message and creates no memory, while the same role with the real stream is accepted
    before and after, and GetMemory reads back the real stream ARN."""
    client = ctx.client("bedrock-agentcore-control")
    iam = ctx.client("iam")
    kinesis = ctx.client("kinesis")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # General-health control: CreateMemory with no dependency at all succeeds.
    good_name = _pattern_safe_name(ctx, "sim2realmemgooddep")
    created = client.create_memory(name=good_name, eventExpiryDuration=7)
    ctx.on_cleanup(lambda: _ac_delete_memory(client, created["memory"]["id"]))
    assert created["memory"]["name"] == good_name

    # Real dependency: an execution role that can actually read/write the real stream,
    # and the stream itself. Both are prerequisites for streamDeliveryResources at all.
    role_arn = _create_memory_execution_role(ctx, iam, account_id)
    real_stream_arn = _create_active_kinesis_stream(ctx, kinesis)
    _grant_stream_access(ctx, iam, role_arn, real_stream_arn)

    # Positive control on the SAME wiring (role + stream): proves the role is fully
    # propagated and that streamDeliveryResources with a real dependency is accepted --
    # ruling out "CreateMemory rejects every streamDeliveryResources request" before the
    # negative below is trusted to mean anything.
    working_name = _pattern_safe_name(ctx, "sim2realmemworking")
    working = _create_memory_with_role_retry(ctx, client, working_name, role_arn, real_stream_arn)
    ctx.on_cleanup(lambda: _ac_delete_memory(client, working["memory"]["id"]))
    assert working["memory"]["status"] in ("CREATING", "ACTIVE"), working["memory"]

    # Break exactly one thing: the same proven-working role, but a well-formed
    # nonexistent stream ARN. Role propagation is already settled (the call above
    # succeeded with this exact role), so a single attempt is conclusive.
    bad_name = _pattern_safe_name(ctx, "sim2realmembaddep")
    fake_stream_arn = f"arn:aws:kinesis:{ctx.region}:{account_id}:stream/sim2real-missing-stream-xyz"
    err = _client_error(
        lambda: client.create_memory(
            name=bad_name,
            eventExpiryDuration=7,
            memoryExecutionRoleArn=role_arn,
            streamDeliveryResources={
                "resources": [
                    {
                        "kinesis": {
                            "dataStreamArn": fake_stream_arn,
                            "contentConfigurations": [{"type": "MEMORY_RECORDS"}],
                        }
                    }
                ]
            },
        )
    )
    assert err["Code"] == "ValidationException", f"expected ValidationException, got {err['Code']}: {err.get('Message')}"
    expected_message = (
        "Memory execution role does not have access to provided Kinesis stream. If the stream is "
        "KMS-encrypted, ensure the role has kms:GenerateDataKey and kms:Decrypt permissions on "
        "the KMS key."
    )
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    # Effect absent: no memory referencing the nonexistent stream was actually created
    # (MemorySummary items expose id/arn, not name, so match on the id-prefix pattern
    # our _pattern_safe_name derives from bad_name).
    found = False
    paginator_token = None
    while True:
        kwargs = {"nextToken": paginator_token} if paginator_token else {}
        page = client.list_memories(**kwargs)
        if any(m.get("id", "").startswith(bad_name) for m in page.get("memories", [])):
            found = True
            break
        paginator_token = page.get("nextToken")
        if not paginator_token:
            break
    assert not found, "a memory referencing the nonexistent stream should not have been created"

    # Restore: the identical call, dependency fixed, succeeds again.
    restore_name = _pattern_safe_name(ctx, "sim2realmemrestore")
    restored = _create_memory_with_role_retry(ctx, client, restore_name, role_arn, real_stream_arn)
    restored_id = restored["memory"]["id"]
    ctx.on_cleanup(lambda: _ac_delete_memory(client, restored_id))

    # Terminal read: an independent GetMemory call (not the mutating CreateMemory's own
    # response) confirms the restored memory is really there, with the dependency wired.
    fetched = client.get_memory(memoryId=restored_id)["memory"]
    assert fetched["name"] == restore_name, fetched
    assert fetched["streamDeliveryResources"]["resources"][0]["kinesis"]["dataStreamArn"] == real_stream_arn, fetched


# AgentCore refuses a delete while the resource is CREATING/UPDATING or still has dependents
# (ValidationException/ConflictException), and an accepted delete completes asynchronously, so a
# teardown waits out transitional statuses and then for the resource to be gone.
_AC_TRANSITIONAL = ("CREATING", "UPDATING", "DELETING", "SYNCHRONIZING")


def _ac_delete_and_wait(get_status, delete, *, what, timeout_s=600.0, interval_s=5.0):
    """Delete once out of a transitional status, then wait for ResourceNotFound; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            last = get_status()
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if last == "DELETED":
            return
        if last not in _AC_TRANSITIONAL:
            try:
                delete()
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code not in ("ConflictException", "ValidationException"):
                    raise
                last = f"{last}; delete refused: {exc}"
        if time.monotonic() >= deadline:
            raise AssertionError(f"teardown: {what} still present after {timeout_s}s ({last})")
        time.sleep(interval_s)


def _ac_delete_memory(control, memory_id):
    _ac_delete_and_wait(
        lambda: control.get_memory(memoryId=memory_id)["memory"]["status"],
        lambda: control.delete_memory(memoryId=memory_id),
        what=f"memory {memory_id}",
    )


def _client_error(fn) -> dict:
    """Return the Error dict of the ClientError fn raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _pattern_safe_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    safe = "".join(c for c in raw if c.isalnum() or c == "_")
    if not safe[:1].isalpha():
        safe = "m" + safe
    return safe[:48]


def _create_memory_execution_role(ctx, iam, account_id: str) -> str:
    role_name = ctx.unique_name("sim2real-agentcore-mem-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {"aws:SourceArn": f"arn:aws:bedrock-agentcore:{ctx.region}:{account_id}:memory/*"},
                },
            }
        ],
    }
    role_resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_resp["Role"]["Arn"]


def _create_active_kinesis_stream(ctx, kinesis, timeout_s: float = 120.0) -> str:
    stream_name = ctx.unique_name("sim2real-agentcore-mem-stream-")
    kinesis.create_stream(StreamName=stream_name, ShardCount=1)
    ctx.on_cleanup(lambda: _best_effort_delete_stream(kinesis, stream_name))
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"]
        if desc["StreamStatus"] == "ACTIVE":
            return desc["StreamARN"]
        time.sleep(5)
    raise AssertionError(f"kinesis stream {stream_name} did not become ACTIVE within {timeout_s}s")


def _best_effort_delete_stream(kinesis, name: str) -> None:
    try:
        kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _grant_stream_access(ctx, iam, role_arn: str, stream_arn: str) -> None:
    role_name = role_arn.rsplit("/", 1)[-1]
    policy_name = ctx.unique_name("sim2real-agentcore-mem-pol-")
    permissions_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "kinesis:PutRecord",
                    "kinesis:PutRecords",
                    "kinesis:DescribeStream",
                    "kinesis:DescribeStreamSummary",
                ],
                "Resource": stream_arn,
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(permissions_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))


def _create_memory_with_role_retry(ctx, client, name: str, role_arn: str, stream_arn: str, timeout_s: float = 90.0):
    """IAM role trust/permissions propagation is eventually consistent; retry past a
    transient role-not-ready rejection instead of treating it as a permanent one."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return client.create_memory(
                name=name,
                eventExpiryDuration=7,
                memoryExecutionRoleArn=role_arn,
                streamDeliveryResources={
                    "resources": [
                        {
                            "kinesis": {
                                "dataStreamArn": stream_arn,
                                "contentConfigurations": [{"type": "MEMORY_RECORDS"}],
                            }
                        }
                    ]
                },
            )
        except ClientError as err:
            message = err.response["Error"].get("Message", "")
            if any(s in message for s in ("trust policy", "Role validation failed", "does not have access")):
                last_err = err
                time.sleep(5)
                continue
            raise
    raise AssertionError(
        f"role {role_arn} never became usable for CreateMemory within {timeout_s}s: "
        f"{last_err.response['Error'] if last_err else None}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
