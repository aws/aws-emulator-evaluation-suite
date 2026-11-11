"""e2e-table-bucket-replication-and-tagging-flow."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-table-bucket-replication-and-tagging-flow"
GROUP = "state-machine"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Source and destination buckets with a table, SSE-S3 encryption, bucket-level replication (backfill of
    the existing table reaches completed) and tags; after teardown every Get on the deleted source bucket
    returns NotFoundException, so no orphaned encryption, replication or tag state survives.
    """
    s3tables = ctx.client("s3tables")
    iam = ctx.client("iam")

    src_arn = s3tables.create_table_bucket(name=ctx.unique_name("sim2real-e2e-src-"))["arn"]
    ctx.on_cleanup(lambda: _delete_bucket_quiet(s3tables, src_arn))
    dst_arn = s3tables.create_table_bucket(name=ctx.unique_name("sim2real-e2e-dst-"))["arn"]
    ctx.on_cleanup(lambda: _delete_bucket_quiet(s3tables, dst_arn))

    namespace = _safe_name(ctx, "sim2real-e2e-ns-")
    table_name = _safe_name(ctx, "sim2real-e2e-tbl-")
    s3tables.create_namespace(tableBucketARN=src_arn, namespace=[namespace])
    ctx.on_cleanup(lambda: _delete_namespace_quiet(s3tables, src_arn, namespace))
    table_arn = s3tables.create_table(
        tableBucketARN=src_arn, namespace=namespace, name=table_name, format="ICEBERG"
    )["tableARN"]
    ctx.on_cleanup(lambda: _delete_table_quiet(s3tables, src_arn, namespace, table_name))

    # Encryption.
    s3tables.put_table_bucket_encryption(
        tableBucketARN=src_arn, encryptionConfiguration={"sseAlgorithm": "AES256"}
    )
    enc = s3tables.get_table_bucket_encryption(tableBucketARN=src_arn)
    got_alg = enc["encryptionConfiguration"]["sseAlgorithm"]
    assert got_alg == "AES256", f"expected sseAlgorithm AES256, got {got_alg!r}"

    # Replication role.
    role_name = ctx.unique_name("sim2real-e2e-replrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "replication.s3tables.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role_quiet(iam, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="s3tables-replication",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "s3tables:*", "Resource": "*"}],
            }
        ),
    )

    replication_config = {"role": role_arn, "rules": [{"destinations": [{"destinationTableBucketARN": dst_arn}]}]}
    put_result = _retry_on_role_propagation(
        lambda: s3tables.put_table_bucket_replication(
            tableBucketARN=src_arn, configuration=replication_config
        )
    )
    assert put_result["versionToken"], "PutTableBucketReplication returned no versionToken"

    replication = s3tables.get_table_bucket_replication(tableBucketARN=src_arn)
    dest = replication["configuration"]["rules"][0]["destinations"][0]
    assert dest["destinationTableBucketARN"] == dst_arn, (
        f"expected destination {dst_arn!r}, got {dest['destinationTableBucketARN']!r}"
    )
    assert replication["configuration"]["role"] == role_arn, (
        f"expected role {role_arn!r}, got {replication['configuration']['role']!r}"
    )

    # Bucket-level replication must actually backfill a table that already existed
    # before the configuration was set, not just accept and echo the config: observe
    # GetTableReplicationStatus for the pre-existing source table reach "completed".
    seen_initial: dict[str, str] = {}

    def _replication_status():
        resp = s3tables.get_table_replication_status(tableArn=table_arn)
        dests = resp.get("destinations", [])
        status = dests[0]["replicationStatus"] if dests else None
        if status is not None and "value" not in seen_initial:
            seen_initial["value"] = status
        return status

    final_status = _poll_until(
        _replication_status, lambda s: s == "completed", timeout_s=180.0, interval_s=10.0
    )
    assert seen_initial.get("value") in ("pending", "completed"), (
        f"unexpected initial replicationStatus: {seen_initial.get('value')!r}"
    )
    assert final_status == "completed", f"replication never reached completed, last={final_status!r}"

    # The real consequence of "completed", observed independently at the destination:
    # the namespace and table now actually exist in the destination bucket (real AWS
    # backfills a table that predates the replication config -- it is not enough that
    # the source reports the job done).
    dst_namespaces = [
        (ns["namespace"][0] if isinstance(ns["namespace"], list) else ns["namespace"])
        for ns in s3tables.list_namespaces(tableBucketARN=dst_arn).get("namespaces", [])
    ]
    assert namespace in dst_namespaces, (
        f"expected replicated namespace {namespace!r} at destination, got {dst_namespaces!r}"
    )
    dst_tables = [
        t["name"] for t in s3tables.list_tables(tableBucketARN=dst_arn, namespace=namespace).get("tables", [])
    ]
    assert table_name in dst_tables, (
        f"expected replicated table {table_name!r} at destination, got {dst_tables!r}"
    )

    # Tags.
    s3tables.tag_resource(resourceArn=src_arn, tags={"env": "sim2real-e2e"})
    tag_list = s3tables.list_tags_for_resource(resourceArn=src_arn)["tags"]
    assert tag_list.get("env") == "sim2real-e2e", f"expected tag env=sim2real-e2e, got {tag_list!r}"

    # Tear down the source bucket's contents explicitly (namespace-then-bucket order).
    s3tables.delete_table(tableBucketARN=src_arn, namespace=namespace, name=table_name)
    s3tables.delete_namespace(tableBucketARN=src_arn, namespace=namespace)
    s3tables.delete_table_bucket(tableBucketARN=src_arn)

    # Cascading deletion: no orphaned encryption, replication config/status, or tags
    # remain for a table bucket (and table) that no longer exist.
    for probe in (
        lambda: s3tables.get_table_bucket_encryption(tableBucketARN=src_arn),
        lambda: s3tables.get_table_bucket_replication(tableBucketARN=src_arn),
        lambda: s3tables.list_tags_for_resource(resourceArn=src_arn),
        lambda: s3tables.get_table_replication_status(tableArn=table_arn),
    ):
        code, message = _error(probe)
        assert code == "NotFoundException", f"expected NotFoundException, got {code}"
        assert message == "The specified bucket does not exist.", (
            f"expected the exact not-found message for deleted bucket {src_arn}, got {message!r}"
        )

    # The destination bucket is not empty: replication put a real namespace/table
    # there, and DeleteTableBucket refuses on a non-empty bucket. Clean up what
    # replication created before removing the bucket itself.
    s3tables.delete_table(tableBucketARN=dst_arn, namespace=namespace, name=table_name)
    s3tables.delete_namespace(tableBucketARN=dst_arn, namespace=namespace)
    s3tables.delete_table_bucket(tableBucketARN=dst_arn)


def _safe_name(ctx, prefix: str) -> str:
    return ctx.unique_name(prefix).replace("-", "_").lower()


def _error(fn):
    """Call fn(); return its (code, message). A success raises: accepting what AWS refuses is a fidelity gap."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed={last!r}")


def _retry_on_role_propagation(fn, timeout_s: float = 45.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code not in ("AccessDeniedException", "ForbiddenException"):
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"replication role never became usable: {last_err}")


def _delete_bucket_quiet(s3tables, bucket_arn: str) -> None:
    try:
        s3tables.delete_table_bucket(tableBucketARN=bucket_arn)
    except s3tables.exceptions.NotFoundException:
        pass


def _delete_namespace_quiet(s3tables, bucket_arn: str, namespace: str) -> None:
    try:
        s3tables.delete_namespace(tableBucketARN=bucket_arn, namespace=namespace)
    except s3tables.exceptions.NotFoundException:
        pass


def _delete_table_quiet(s3tables, bucket_arn: str, namespace: str, name: str) -> None:
    try:
        s3tables.delete_table(tableBucketARN=bucket_arn, namespace=namespace, name=name)
    except s3tables.exceptions.NotFoundException:
        pass


def _delete_role_quiet(iam, role_name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName="s3tables-replication")
    except iam.exceptions.NoSuchEntityException:
        pass
    try:
        iam.delete_role(RoleName=role_name)
    except iam.exceptions.NoSuchEntityException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
