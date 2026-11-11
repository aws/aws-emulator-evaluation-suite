"""create-stream-invalid-target-arn-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-stream-invalid-target-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["dsql"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStream rejects a Kinesis target whose IAM role lives in an account the caller cannot use
    (no trust/assume-role path), creates no stream, while a syntactically valid target (real Kinesis
    stream + IAM role in the caller's own account) is accepted."""
    dsql = ctx.client("dsql")

    created = dsql.create_cluster(deletionProtectionEnabled=False, tags={"ManagedBy": "sim2real-behav"})
    cluster_id = created["identifier"]
    ctx.on_cleanup(lambda: _delete_cluster(ctx, cluster_id))
    _poll_until(
        lambda: dsql.get_cluster(identifier=cluster_id)["status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=300.0,
        interval_s=5.0,
    )

    # Boundary: roleArn points at a foreign/nonexistent account -> DSQL cannot establish the
    # trust relationship needed to assume it, so this is rejected as AccessDeniedException,
    # not a shape-only ValidationException.
    bad_target = {
        "kinesis": {
            "streamArn": "not-a-kinesis-arn-at-all",
            "roleArn": "arn:aws:iam::111122223333:role/sim2real-does-not-matter",
        }
    }
    code, message = _error(
        lambda: dsql.create_stream(
            clusterIdentifier=cluster_id, targetDefinition=bad_target, ordering="UNORDERED", format="JSON"
        )
    )
    assert code == "AccessDeniedException", code
    assert message == "Cross-account pass role is not allowed.", message

    # Effect absent: no stream was created on this cluster.
    streams = dsql.list_streams(clusterIdentifier=cluster_id)["streams"]
    assert streams == [], f"a stream was created despite the invalid target: {streams}"

    # Positive control: a real Kinesis stream + service role IS accepted.
    target = _create_cdc_target(ctx, cluster_id)

    def _attempt_create_stream():
        return dsql.create_stream(
            clusterIdentifier=cluster_id,
            targetDefinition={"kinesis": {"streamArn": target["stream_arn"], "roleArn": target["role_arn"]}},
            ordering="UNORDERED",
            format="JSON",
        )

    good_resp = _retry_while_role_not_ready(_attempt_create_stream, timeout_s=60.0, interval_s=5.0)
    stream_id = good_resp["streamIdentifier"]
    ctx.on_cleanup(lambda: _delete_stream_quiet(ctx, cluster_id, stream_id))
    assert good_resp["status"] in ("CREATING", "ACTIVE")

    # Independent read at the destination: the stream is really there and reaches ACTIVE,
    # not just what the mutating call itself echoed back.
    active_stream = _poll_until(
        lambda: dsql.get_stream(clusterIdentifier=cluster_id, streamIdentifier=stream_id),
        lambda r: r["status"] in ("ACTIVE", "FAILED"),
        timeout_s=300.0,
        interval_s=5.0,
    )
    assert active_stream["status"] == "ACTIVE", f"stream reached {active_stream['status']!r} instead of ACTIVE"
    listed_good = dsql.list_streams(clusterIdentifier=cluster_id)["streams"]
    assert any(s["streamIdentifier"] == stream_id for s in listed_good), listed_good


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _error(fn):
    """Call fn() and return its ClientError (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _retry_while_role_not_ready(fn, *, timeout_s=60.0, interval_s=5.0):
    """IAM role creation is eventually consistent. While DSQL can't yet see the new role, real AWS
    answers either AccessDeniedException or a
    ValidationException whose message says the role "doesn't exist or doesn't allow Aurora DSQL
    access" -- a same-account role that is merely not-yet-visible reads identically to a role that
    truly doesn't exist until it propagates. Retry briefly on both; anything else raises immediately."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            transient = code == "AccessDeniedException" or (
                code == "ValidationException" and "doesn't allow Aurora DSQL access" in message
            )
            if not transient:
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"role still not usable after {timeout_s}s: {last_exc}")


def _create_cdc_target(ctx, cluster_id):

    kinesis = ctx.client("kinesis")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region

    stream_name = ctx.unique_name("sim2real-dsql-cdc-")
    kinesis.create_stream(StreamName=stream_name, ShardCount=1, Tags={"ManagedBy": "sim2real-behav"})
    ctx.on_cleanup(lambda: _delete_kinesis_stream_quiet(ctx, stream_name))
    _poll_until(
        lambda: kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"][
            "StreamStatus"
        ],
        lambda s: s == "ACTIVE",
        timeout_s=120.0,
        interval_s=3.0,
    )
    stream_arn = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"][
        "StreamARN"
    ]

    role_name = ctx.unique_name("sim2real-dsql-cdc-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DSQLAssumeRole",
                "Effect": "Allow",
                "Principal": {"Service": "dsql.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {
                        "aws:SourceArn": f"arn:aws:dsql:{region}:{account_id}:cluster/{cluster_id}/stream/*"
                    },
                },
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "ManagedBy", "Value": "sim2real-behav"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_iam_role_quiet(ctx, role_name))

    perm_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "KinesisAccess",
                "Effect": "Allow",
                "Action": [
                    "kinesis:PutRecord",
                    "kinesis:PutRecords",
                    "kinesis:DescribeStreamSummary",
                    "kinesis:ListShards",
                ],
                "Resource": stream_arn,
            }
        ],
    }
    policy_name = "sim2real-dsql-cdc-kinesis-access"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(perm_policy))
    ctx.on_cleanup(lambda: _delete_role_policy_quiet(ctx, role_name, policy_name))

    return {"role_arn": role_arn, "stream_arn": stream_arn}


def _delete_kinesis_stream_quiet(ctx, stream_name):
    from botocore.exceptions import ClientError

    try:
        ctx.client("kinesis").delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_iam_role_quiet(ctx, role_name):
    from botocore.exceptions import ClientError

    try:
        ctx.client("iam").delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_role_policy_quiet(ctx, role_name, policy_name):
    from botocore.exceptions import ClientError

    try:
        ctx.client("iam").delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_stream_quiet(ctx, cluster_id, stream_id):
    from botocore.exceptions import ClientError

    try:
        ctx.client("dsql").delete_stream(clusterIdentifier=cluster_id, streamIdentifier=stream_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_cluster(ctx, identifier):
    from botocore.exceptions import ClientError

    dsql = ctx.client("dsql")
    try:
        dsql.update_cluster(identifier=identifier, deletionProtectionEnabled=False)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        dsql.delete_cluster(identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
