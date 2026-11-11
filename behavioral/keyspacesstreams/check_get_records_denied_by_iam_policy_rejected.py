"""get-records-denied-by-iam-policy-rejected."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-records-denied-by-iam-policy-rejected"
GROUP = "overly-permissive"
SERVICES = ["keyspacesstreams"]


@tags("axis:rejection", "cap:c2", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A principal allowed GetStream/GetShardIterator but not GetRecords gets
    AccessDeniedException from GetRecords while the admin caller reads the same shard,
    and the identical call succeeds once that principal is granted GetRecords."""
    ks = _clean_name(ctx, "sim2realkssks")
    tbl = _clean_name(ctx, "sim2realksstbl")
    kc = ctx.client("keyspaces")
    kss = ctx.client("keyspacesstreams")
    iam = ctx.client("iam")

    kc.create_keyspace(keyspaceName=ks, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_keyspace_best_effort(ctx, ks))
    _create_cdc_table(ctx, ks, tbl, "NEW_IMAGE")
    stream_arn = _wait_table_cdc_status(ctx, ks, tbl, "ENABLED", timeout_s=180)
    stream = _poll_stream_status(ctx, stream_arn, "ENABLED", timeout_s=120)
    shard_id = stream["shards"][0]["shardId"]

    iterator = kss.get_shard_iterator(
        streamArn=stream_arn, shardId=shard_id, shardIteratorType="TRIM_HORIZON"
    )["shardIterator"]

    # Positive control, before any restricted principal exists: the admin caller can
    # read records through this stream/shard, so the denial below is measured against
    # a target that is otherwise healthy for this call.
    control = kss.get_records(shardIterator=iterator)
    assert control["changeRecords"] == [], (
        "expected the admin caller's GetRecords to succeed with an empty (but present) "
        f"changeRecords list, got {control['changeRecords']!r}"
    )

    limited_client, user_name, policy_name, system_keyspace_arn = _create_limited_client(
        ctx, stream_arn
    )

    # Poll: the limited principal's credentials/policy need a moment to
    # propagate. GetStream is allowed for this principal, so use it as the
    # readiness probe.
    deadline = time.monotonic() + 120
    ready = False
    last_exc = None
    while time.monotonic() < deadline:
        try:
            limited_client.get_stream(streamArn=stream_arn)
            ready = True
            break
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            time.sleep(5)
    assert ready, f"limited IAM principal never became usable for the allowed action: {last_exc!r}"

    limited_iterator = limited_client.get_shard_iterator(
        streamArn=stream_arn, shardId=shard_id, shardIteratorType="TRIM_HORIZON"
    )["shardIterator"]

    err = _error(lambda: limited_client.get_records(shardIterator=limited_iterator))
    assert err["Code"] == "AccessDeniedException", (
        f"expected AccessDeniedException from the IAM-limited principal's GetRecords, "
        f"got {err['Code']!r}"
    )
    expected = (
        f"User: arn:aws:iam::{ctx.account}:user/{user_name} is not authorized to perform: "
        f"cassandra:GetRecords on resource: {stream_arn} because no identity-based policy "
        f"allows the cassandra:GetRecords action"
    )
    assert err["Message"] == expected, (
        f"expected the denial message {expected!r}, got {err['Message']!r}"
    )

    # Restore: grant the withheld action to the SAME principal, and demand the
    # identical call now succeeds, so the denial is shown to come from the missing
    # permission -- not just a different principal's read standing in for the restore leg.
    iam.put_user_policy(
        UserName=user_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "cassandra:GetStream",
                        "cassandra:GetShardIterator",
                        "cassandra:GetRecords",
                    ],
                    "Resource": stream_arn,
                },
                {
                    "Effect": "Allow",
                    "Action": "cassandra:Select",
                    "Resource": system_keyspace_arn,
                },
            ],
        }),
    )

    restored = None
    last_exc = None
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            fresh_iterator = limited_client.get_shard_iterator(
                streamArn=stream_arn, shardId=shard_id, shardIteratorType="TRIM_HORIZON"
            )["shardIterator"]
            restored = limited_client.get_records(shardIterator=fresh_iterator)
            break
        except Exception as exc:  # noqa: BLE001 -- IAM policy update propagation lag
            last_exc = exc
            time.sleep(3)
    assert restored is not None, (
        "expected the identical GetRecords call to succeed once cassandra:GetRecords is "
        f"granted to the same principal; last error: {last_exc!r}"
    )
    assert restored["changeRecords"] == [], (
        "expected the now-permitted principal's GetRecords to succeed with an empty (but "
        f"present) changeRecords list, got {restored['changeRecords']!r}"
    )


# ===== helpers =====


def _create_limited_client(ctx, stream_arn: str):
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-kss-iamuser-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_user_best_effort(ctx, user_name))

    # GetStream (like any CDC "view" call) also requires baseline read
    # permission on the system keyspace, per the Keyspaces CDC permissions
    # model, in addition to the stream-scoped action itself.
    partition_arn = stream_arn.split(":cassandra:", 1)
    account_region_prefix = partition_arn[1].split(":/keyspace/", 1)[0]
    system_keyspace_arn = f"arn:aws:cassandra:{account_region_prefix}:/keyspace/system*"

    policy_name = "kss-read-only-no-getrecords"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["cassandra:GetStream", "cassandra:GetShardIterator"],
                "Resource": stream_arn,
            },
            {
                "Effect": "Allow",
                "Action": "cassandra:Select",
                "Resource": system_keyspace_arn,
            },
        ],
    }
    iam.put_user_policy(
        UserName=user_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(
        lambda: _best_effort(lambda: iam.delete_user_policy(UserName=user_name, PolicyName=policy_name))
    )

    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"])
        )
    )

    from botocore.config import Config

    # The re-signing idiom (ctx.client(..., creds=...)): keeps this target's endpoint and
    # TLS wiring — real AWS's endpoint-ruleset resolution, or the emulator's shared base URL
    # — while swapping in the limited principal's identity, instead of hand-rolling a
    # boto3.client() that would always dial real AWS whatever the target.
    client = ctx.client(
        "keyspacesstreams",
        creds={
            "aws_access_key_id": key["AccessKeyId"],
            "aws_secret_access_key": key["SecretAccessKey"],
        },
        config=Config(retries={"max_attempts": 8, "mode": "standard"}),
    )
    return client, user_name, policy_name, system_keyspace_arn


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_user_best_effort(ctx, user_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_user(UserName=user_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _error(fn):
    """Call fn(); return its ClientError's Error member (Code and Message). An unexpected
    SUCCESS raises: a target that serves records to a principal real AWS refuses must not
    read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(
        f"expected GetRecords to be denied, but the call SUCCEEDED and returned {result!r}"
    )


def _clean_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    return re.sub(r"[^a-zA-Z0-9_]", "", raw)[:48]


def _retry_create_table(kc, timeout_s: float = 60, **kwargs) -> None:
    """CreateTable can trail CreateKeyspace by a few seconds while the new
    keyspace propagates; retry on ResourceNotFoundException instead of
    failing immediately."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            kc.create_table(**kwargs)
            return
        except kc.exceptions.ResourceNotFoundException:
            if time.monotonic() > deadline:
                raise
            time.sleep(3)


def _create_cdc_table(ctx, keyspace: str, table: str, view_type: str) -> None:
    kc = ctx.client("keyspaces")
    _retry_create_table(
        kc,
        keyspaceName=keyspace,
        tableName=table,
        schemaDefinition={
            "allColumns": [
                {"name": "pk", "type": "text"},
                {"name": "ck", "type": "text"},
            ],
            "partitionKeys": [{"name": "pk"}],
            "clusteringKeys": [{"name": "ck", "orderBy": "ASC"}],
        },
        capacitySpecification={"throughputMode": "PAY_PER_REQUEST"},
        cdcSpecification={"status": "ENABLED", "viewType": view_type},
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table_best_effort(ctx, keyspace, table))


def _wait_table_cdc_status(ctx, keyspace: str, table: str, status: str, timeout_s: float) -> str:
    kc = ctx.client("keyspaces")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = kc.get_table(keyspaceName=keyspace, tableName=table)
        except kc.exceptions.ResourceNotFoundException:
            time.sleep(3)
            continue
        cdc = resp.get("cdcSpecification") or {}
        if resp.get("status") == "ACTIVE" and cdc.get("status") == status:
            return resp["latestStreamArn"]
        time.sleep(3)
    raise AssertionError(f"table/CDC did not reach ACTIVE/{status} within {timeout_s}s")


def _poll_stream_status(ctx, stream_arn: str, status: str, timeout_s: float) -> dict:
    kss = ctx.client("keyspacesstreams")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = kss.get_stream(streamArn=stream_arn)
        if last["streamStatus"] == status:
            return last
        time.sleep(3)
    raise AssertionError(f"stream never reached {status}, last={last}")


def _delete_table_best_effort(ctx, keyspace: str, table: str) -> None:
    kc = ctx.client("keyspaces")
    try:
        kc.delete_table(keyspaceName=keyspace, tableName=table)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_keyspace_best_effort(ctx, keyspace: str) -> None:
    kc = ctx.client("keyspaces")
    deadline = time.monotonic() + 120
    while True:
        try:
            kc.delete_keyspace(keyspaceName=keyspace)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            # A table delete still in progress refuses the keyspace delete; retry to the deadline.
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
