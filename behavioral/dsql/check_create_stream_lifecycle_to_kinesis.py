"""create-stream-lifecycle-to-kinesis."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-stream-lifecycle-to-kinesis"
GROUP = "deploy"
SERVICES = ["dsql"]

#: Cluster deletion budget; named so the Probe derives a per-check deadline above it.
_DELETE_TIMEOUT_S = 900.0


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "dp:native", "plane:control", "plane:data")
def run(ctx) -> None:
    """A tagged cluster with a resource policy and a CDC stream to Kinesis reaches ACTIVE, a row written over
    the Postgres wire protocol arrives as a change record on the Kinesis stream, and stream, policy and
    cluster are each really removed when deleted in reverse order."""
    import psycopg

    dsql = ctx.client("dsql")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    env_tag = ctx.unique_name("sim2real-behav-deploy")
    created = dsql.create_cluster(
        deletionProtectionEnabled=False, tags={"Environment": env_tag, "ManagedBy": "sim2real-behav"}
    )
    cluster_id = created["identifier"]
    cluster_arn = created["arn"]
    ctx.on_cleanup(lambda: _delete_cluster(ctx, cluster_id))
    _poll_until(
        lambda: dsql.get_cluster(identifier=cluster_id)["status"],
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=300.0,
        interval_s=5.0,
    )
    active = dsql.get_cluster(identifier=cluster_id)
    assert active["status"] == "ACTIVE"
    assert active["tags"].get("Environment") == env_tag
    assert dsql.list_tags_for_resource(resourceArn=cluster_arn)["tags"].get("ManagedBy") == "sim2real-behav"

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowAccountConnect",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "dsql:DbConnect",
                "Resource": "*",
            }
        ],
    }
    put_policy = dsql.put_cluster_policy(identifier=cluster_id, policy=json.dumps(policy_doc))
    policy_version = put_policy["policyVersion"]
    fetched_policy = dsql.get_cluster_policy(identifier=cluster_id)
    assert json.loads(fetched_policy["policy"]) == policy_doc
    assert fetched_policy["policyVersion"] == policy_version

    target = _create_cdc_target(ctx, cluster_id)

    def _attempt_create_stream():
        return dsql.create_stream(
            clusterIdentifier=cluster_id,
            targetDefinition={"kinesis": {"streamArn": target["stream_arn"], "roleArn": target["role_arn"]}},
            ordering="UNORDERED",
            format="JSON",
        )

    created_stream = _retry_while_role_not_ready(_attempt_create_stream, timeout_s=90.0, interval_s=5.0)
    stream_id = created_stream["streamIdentifier"]
    assert created_stream["ordering"] == "UNORDERED"
    assert created_stream["format"] == "JSON"

    active_stream = _poll_until(
        lambda: dsql.get_stream(clusterIdentifier=cluster_id, streamIdentifier=stream_id),
        lambda r: r["status"] in ("ACTIVE", "FAILED"),
        timeout_s=300.0,
        interval_s=5.0,
    )
    assert active_stream["status"] == "ACTIVE", f"stream reached {active_stream['status']!r} instead of ACTIVE"

    listed = dsql.list_streams(clusterIdentifier=cluster_id)["streams"]
    assert any(s["streamIdentifier"] == stream_id for s in listed)

    # The stream being ACTIVE and listed proves the control-plane object exists; it proves nothing
    # about whether the pipeline actually moves data. Write a real row over the Postgres wire
    # protocol and read the resulting CDC record back out of the Kinesis stream it targets -- a
    # target that fakes stream status transitions without ever delivering data cannot pass this.
    kinesis = ctx.client("kinesis")
    marker = ctx.unique_name("sim2real-dsql-cdc-row-")
    address, port = ctx.endpoint_host(active["endpoint"], 5432)
    conn = _connect_with_retry(ctx, psycopg, address, _admin_token(dsql, active["endpoint"], ctx.region), port=port)
    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("CREATE TABLE sim2real_cdc_probe (id INT PRIMARY KEY, payload TEXT)")
        shard_id = kinesis.list_shards(StreamName=target["stream_name"])["Shards"][0]["ShardId"]
        shard_iterator = kinesis.get_shard_iterator(
            StreamName=target["stream_name"], ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
        )["ShardIterator"]
        with conn.cursor() as cur:
            cur.execute("INSERT INTO sim2real_cdc_probe (id, payload) VALUES (1, %s)", (marker,))
    finally:
        conn.close()

    cdc_record = _poll_for_cdc_record(kinesis, shard_iterator, marker, timeout_s=120.0)
    assert cdc_record is not None, f"no CDC record carrying marker {marker!r} arrived on the target Kinesis stream"

    # The deployment is a coherent unit: cluster is enumerable, ACTIVE, still tagged, still has its
    # policy and stream attached, all at once.
    all_clusters = dsql.list_clusters()["clusters"]
    assert any(c["identifier"] == cluster_id for c in all_clusters)
    assert dsql.get_cluster(identifier=cluster_id)["status"] == "ACTIVE"

    # Tear down in reverse dependency order: stream, then policy, then cluster — verifying each step
    # actually removes the resource.
    dsql.delete_stream(clusterIdentifier=cluster_id, streamIdentifier=stream_id)

    def _stream_probe():
        try:
            return dsql.get_stream(clusterIdentifier=cluster_id, streamIdentifier=stream_id)["status"]
        except Exception as exc:  # noqa: BLE001 - narrowed below
            from botocore.exceptions import ClientError

            if isinstance(exc, ClientError) and exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return "DELETED"
            raise

    final_status = _poll_until(_stream_probe, lambda s: s == "DELETED", timeout_s=300.0, interval_s=5.0)
    assert final_status == "DELETED"
    listed_after = dsql.list_streams(clusterIdentifier=cluster_id)["streams"]
    assert not any(s["streamIdentifier"] == stream_id for s in listed_after)

    dsql.delete_cluster_policy(identifier=cluster_id)
    policy_gone_code, policy_gone_message = _error(lambda: dsql.get_cluster_policy(identifier=cluster_id))
    assert policy_gone_code == "ResourceNotFoundException", policy_gone_code
    assert policy_gone_message == (
        f"Aurora DSQL can't find the policy for the resource {cluster_id}. Verify that the policy exists."
    ), policy_gone_message

    dsql.delete_cluster(identifier=cluster_id)

    def _cluster_probe():
        try:
            return dsql.get_cluster(identifier=cluster_id)["status"]
        except Exception as exc:  # noqa: BLE001 - narrowed below
            from botocore.exceptions import ClientError

            if isinstance(exc, ClientError) and exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return "DELETED"
            raise

    cluster_final = _poll_until(_cluster_probe, lambda s: s == "DELETED", timeout_s=_DELETE_TIMEOUT_S, interval_s=10.0)
    assert cluster_final == "DELETED"


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
    """Call fn(); return its ClientError (code, message). A success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _retry_while_role_not_ready(fn, *, timeout_s=60.0, interval_s=5.0):
    """IAM role creation is eventually consistent. On real AWS, DSQL rejects CreateStream with
    ValidationException (not AccessDeniedException) -- "Aurora DSQL can't access the specified
    IAM role ... because the role doesn't exist or doesn't allow Aurora DSQL access" -- while the
    new role/trust-policy/inline-policy has not yet propagated. Retry only that specific, transient
    signature; any other error (including a genuinely wrong role) surfaces immediately."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "ValidationException" or "doesn't allow Aurora DSQL access" not in err.get(
                "Message", ""
            ):
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"role still not accepted by DSQL after {timeout_s}s: {last_exc}")


def _admin_token(dsql, endpoint, region):
    return dsql.generate_db_connect_admin_auth_token(Hostname=endpoint, Region=region, ExpiresIn=900)


def _connect_with_retry(ctx, psycopg, endpoint, token, timeout_s=90.0, interval_s=3.0, port=5432):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return psycopg.connect(
                host=endpoint, port=port, dbname="postgres", user="admin",
                password=token, connect_timeout=10, **_tls(),
                cursor_factory=psycopg.ClientCursor,
            )
        except Exception as err:  # noqa: BLE001 - connection can transiently fail right after ACTIVE
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"could not open a Postgres wire connection to {endpoint}: {last_err}")


def _tls() -> dict:
    """libpq TLS settings: the session is encrypted without verifying the server's identity."""
    return {"sslmode": "require"}


def _poll_for_cdc_record(kinesis, shard_iterator, marker, timeout_s=120.0, interval_s=3.0):
    iterator = shard_iterator
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = kinesis.get_records(ShardIterator=iterator, Limit=100)
        for record in resp["Records"]:
            if marker.encode("utf-8") in record["Data"]:
                return record
        iterator = resp["NextShardIterator"]
        time.sleep(interval_s)
    return None


def _create_cdc_target(ctx, cluster_id):
    kinesis = ctx.client("kinesis")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region

    stream_name = ctx.unique_name("sim2real-dsql-cdc-")
    kinesis.create_stream(StreamName=stream_name, ShardCount=1)
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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
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

    return {"role_arn": role_arn, "stream_arn": stream_arn, "stream_name": stream_name}


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
