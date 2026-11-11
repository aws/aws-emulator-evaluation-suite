"""e2e-bucket-namespace-table-replicate-tag-teardown."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-bucket-namespace-table-replicate-tag-teardown"
GROUP = "e2e"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Bucket, namespace and table lifecycle with tagging and table replication progressing from pending to
    completed, then explicit teardown where every deleted resource reads back as NotFoundException."""
    s3tables = ctx.client("s3tables")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    src_bucket_name = ctx.unique_name("sim2real-s3t-src-")
    dst_bucket_name = ctx.unique_name("sim2real-s3t-dst-")
    src_bucket_arn = s3tables.create_table_bucket(name=src_bucket_name)["arn"]
    ctx.on_cleanup(lambda: _safe_empty_and_delete_bucket(s3tables, src_bucket_arn))
    dst_bucket_arn = s3tables.create_table_bucket(name=dst_bucket_name)["arn"]
    ctx.on_cleanup(lambda: _safe_empty_and_delete_bucket(s3tables, dst_bucket_arn))

    namespace_name = _sanitize(ctx.unique_name("sim2real_ns_"))
    s3tables.create_namespace(tableBucketARN=src_bucket_arn, namespace=[namespace_name])

    table_name = _sanitize(ctx.unique_name("sim2real_tbl_"))
    table_arn = s3tables.create_table(
        tableBucketARN=src_bucket_arn, namespace=namespace_name, name=table_name, format="ICEBERG"
    )["tableARN"]

    s3tables.tag_resource(resourceArn=table_arn, tags={"sim2real-purpose": "e2e-replication-test"})
    table_tags = s3tables.list_tags_for_resource(resourceArn=table_arn)["tags"]
    assert table_tags["sim2real-purpose"] == "e2e-replication-test", (
        f"expected tag sim2real-purpose=e2e-replication-test on {table_arn}, got {table_tags!r}"
    )

    role_arn = _create_replication_role(ctx, account_id, src_bucket_arn, dst_bucket_arn)
    _enable_replication_with_retry(s3tables, table_arn, role_arn, dst_bucket_arn)

    status_resp = _poll_until(
        lambda: s3tables.get_table_replication_status(tableArn=table_arn),
        lambda r: bool(r.get("destinations")) and r["destinations"][0]["replicationStatus"] != "pending",
        timeout_s=240.0,
        interval_s=10.0,
    )
    observed_status = status_resp["destinations"][0]["replicationStatus"]
    assert observed_status == "completed", (
        f"expected replicationStatus=completed for {table_arn}, got {observed_status!r}"
    )
    assert status_resp["sourceTableArn"] == table_arn, (
        f"expected sourceTableArn={table_arn}, got {status_resp['sourceTableArn']!r}"
    )

    # Explicit, ordered teardown: replication config -> table -> namespace -> bucket.
    version_token = s3tables.get_table_replication(tableArn=table_arn)["versionToken"]
    s3tables.delete_table_replication(tableArn=table_arn, versionToken=version_token)
    code, message = _error(lambda: s3tables.get_table_replication(tableArn=table_arn))
    assert code == "NotFoundException", f"expected NotFoundException on deleted replication for {table_arn}, got {code!r}"
    assert message == "The specified replication configuration does not exist.", (
        f"expected the exact not-found message for the deleted replication, got {message!r}"
    )

    _safe_empty_and_delete_bucket(s3tables, dst_bucket_arn)
    code, message = _error(lambda: s3tables.get_table_bucket(tableBucketARN=dst_bucket_arn))
    assert code == "NotFoundException", f"expected NotFoundException on deleted bucket {dst_bucket_arn}, got {code!r}"
    assert message == "The specified bucket does not exist.", (
        f"expected the exact not-found message for deleted bucket {dst_bucket_arn}, got {message!r}"
    )

    s3tables.delete_table(tableBucketARN=src_bucket_arn, namespace=namespace_name, name=table_name)
    code, message = _error(
        lambda: s3tables.get_table(tableBucketARN=src_bucket_arn, namespace=namespace_name, name=table_name)
    )
    assert code == "NotFoundException", f"expected NotFoundException on deleted table {table_arn}, got {code!r}"
    assert message == "The specified table does not exist.", (
        f"expected the exact not-found message for deleted table {table_arn}, got {message!r}"
    )

    s3tables.delete_namespace(tableBucketARN=src_bucket_arn, namespace=namespace_name)
    code, message = _error(lambda: s3tables.get_namespace(tableBucketARN=src_bucket_arn, namespace=namespace_name))
    assert code == "NotFoundException", (
        f"expected NotFoundException on deleted namespace {namespace_name}, got {code!r}"
    )
    assert message == "The specified namespace does not exist.", (
        f"expected the exact not-found message for deleted namespace {namespace_name}, got {message!r}"
    )

    s3tables.delete_table_bucket(tableBucketARN=src_bucket_arn)
    code, message = _error(lambda: s3tables.get_table_bucket(tableBucketARN=src_bucket_arn))
    assert code == "NotFoundException", f"expected NotFoundException on deleted bucket {src_bucket_arn}, got {code!r}"
    assert message == "The specified bucket does not exist.", (
        f"expected the exact not-found message for deleted bucket {src_bucket_arn}, got {message!r}"
    )


def _sanitize(name: str) -> str:
    return re.sub(r"[^0-9a-z_]", "_", name.lower())


def _error(fn):
    """Call fn(); return its (code, message). A success raises: accepting what AWS refuses is a fidelity gap."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed={last!r}")


def _safe_empty_and_delete_bucket(s3tables, bucket_arn: str) -> None:
    try:
        namespaces: list[str] = []
        token = None
        while True:
            kwargs = {"tableBucketARN": bucket_arn}
            if token:
                kwargs["continuationToken"] = token
            resp = s3tables.list_namespaces(**kwargs)
            for ns in resp.get("namespaces", []):
                ns_name = ns["namespace"]
                namespaces.append(ns_name[0] if isinstance(ns_name, list) else ns_name)
            token = resp.get("continuationToken")
            if not token:
                break
        for ns_name in namespaces:
            try:
                ttoken = None
                tables: list[str] = []
                while True:
                    kwargs = {"tableBucketARN": bucket_arn, "namespace": ns_name}
                    if ttoken:
                        kwargs["continuationToken"] = ttoken
                    tresp = s3tables.list_tables(**kwargs)
                    tables.extend(t["name"] for t in tresp.get("tables", []))
                    ttoken = tresp.get("continuationToken")
                    if not ttoken:
                        break
                for t_name in tables:
                    try:
                        s3tables.delete_table(tableBucketARN=bucket_arn, namespace=ns_name, name=t_name)
                    except s3tables.exceptions.NotFoundException:
                        pass
                s3tables.delete_namespace(tableBucketARN=bucket_arn, namespace=ns_name)
            except s3tables.exceptions.NotFoundException:
                pass
        s3tables.delete_table_bucket(tableBucketARN=bucket_arn)
    except s3tables.exceptions.NotFoundException:
        pass


def _create_replication_role(ctx, account_id: str, src_bucket_arn: str, dst_bucket_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-s3t-repl-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "replication.s3tables.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            }
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))

    permissions_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3tables:*"],
                "Resource": [
                    src_bucket_arn,
                    f"{src_bucket_arn}/*",
                    dst_bucket_arn,
                    f"{dst_bucket_arn}/*",
                ],
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sim2real-s3t-repl-policy", PolicyDocument=json.dumps(permissions_policy)
    )
    return role_arn


def _delete_role(iam, role_name: str) -> None:
    try:
        for policy_name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except iam.exceptions.NoSuchEntityException:
        pass
    try:
        iam.delete_role(RoleName=role_name)
    except iam.exceptions.NoSuchEntityException:
        pass


def _enable_replication_with_retry(s3tables, table_arn: str, role_arn: str, dst_bucket_arn: str, timeout_s=90.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return s3tables.put_table_replication(
                tableArn=table_arn,
                configuration={
                    "role": role_arn,
                    "rules": [{"destinations": [{"destinationTableBucketARN": dst_bucket_arn}]}],
                },
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ForbiddenException"):
                # IAM role trust/permissions propagation is eventually consistent.
                last_err = e
                time.sleep(5)
                continue
            raise
    raise AssertionError(f"replication was never accepted within {timeout_s}s: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

