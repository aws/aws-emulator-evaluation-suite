"""e2e-table-bucket-replication-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-table-bucket-replication-lifecycle"
GROUP = "state-machine"
SERVICES = ["s3tables"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """With bucket- and table-level replication put (both return a versionToken), GetTableReplicationStatus
    reaches completed, and GetTable in the destination bucket returns the reported destinationTableArn
    under the same namespace and name."""
    s3tables = ctx.client("s3tables")
    iam = ctx.client("iam")

    resource_tags = {"sim2real-purpose": "e2e-table-bucket-replication-lifecycle"}

    src_name = ctx.unique_name("sim2real-s3t-repl-src-")
    dst_name = ctx.unique_name("sim2real-s3t-repl-dst-")
    src_arn = s3tables.create_table_bucket(name=src_name, tags=resource_tags)["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=src_arn))
    dst_arn = s3tables.create_table_bucket(name=dst_name, tags=resource_tags)["arn"]
    ctx.on_cleanup(lambda: s3tables.delete_table_bucket(tableBucketARN=dst_arn))

    ns_name = ctx.unique_name("sim2real_ns_").replace("-", "_")
    s3tables.create_namespace(tableBucketARN=src_arn, namespace=[ns_name])
    ctx.on_cleanup(lambda: s3tables.delete_namespace(tableBucketARN=src_arn, namespace=ns_name))

    table_name = ctx.unique_name("sim2real_tbl_").replace("-", "_")
    table_arn = s3tables.create_table(
        tableBucketARN=src_arn, namespace=ns_name, name=table_name, format="ICEBERG", tags=resource_tags
    )["tableARN"]
    ctx.on_cleanup(
        lambda: s3tables.delete_table(tableBucketARN=src_arn, namespace=ns_name, name=table_name)
    )

    # Replication creates its own copy of the namespace/table at the destination
    # bucket -- that copy is this check's responsibility too, and it must be gone
    # before the destination bucket itself can be deleted.
    ctx.on_cleanup(lambda: _delete_if_present(lambda: s3tables.delete_table(
        tableBucketARN=dst_arn, namespace=ns_name, name=table_name
    )))
    ctx.on_cleanup(lambda: _delete_if_present(lambda: s3tables.delete_namespace(
        tableBucketARN=dst_arn, namespace=ns_name
    )))

    role_name = ctx.unique_name("sim2real-s3t-repl-role-")
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": k, "Value": v} for k, v in resource_tags.items()],
    )["Role"]["Arn"]

    def _delete_role():
        iam.delete_role_policy(RoleName=role_name, PolicyName="replication-perms")
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)

    perms_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3tables:GetTable",
                    "s3tables:GetTableMetadataLocation",
                    "s3tables:GetTableMaintenanceConfiguration",
                    "s3tables:GetTableData",
                ],
                "Resource": f"{src_arn}/table/*",
            },
            {"Effect": "Allow", "Action": ["s3tables:ListTables"], "Resource": src_arn},
            {
                "Effect": "Allow",
                "Action": ["s3tables:CreateTable", "s3tables:CreateNamespace"],
                "Resource": dst_arn,
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3tables:PutTableData",
                    "s3tables:GetTableData",
                    "s3tables:UpdateTableMetadataLocation",
                    "s3tables:PutTableMaintenanceConfiguration",
                ],
                "Resource": f"{dst_arn}/table/*",
            },
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="replication-perms", PolicyDocument=json.dumps(perms_policy)
    )

    bucket_repl_config = {"role": role_arn, "rules": [{"destinations": [{"destinationTableBucketARN": dst_arn}]}]}
    bucket_repl_version = _retry_on_role_propagation(
        lambda: s3tables.put_table_bucket_replication(
            tableBucketARN=src_arn, configuration=bucket_repl_config
        )
    )["versionToken"]
    ctx.on_cleanup(
        lambda: s3tables.delete_table_bucket_replication(tableBucketARN=src_arn)
    )

    table_repl_config = {"role": role_arn, "rules": [{"destinations": [{"destinationTableBucketARN": dst_arn}]}]}
    table_repl_version = _retry_on_role_propagation(
        lambda: s3tables.put_table_replication(tableArn=table_arn, configuration=table_repl_config)
    )["versionToken"]

    def _delete_table_repl():
        current = s3tables.get_table_replication(tableArn=table_arn)["versionToken"]
        s3tables.delete_table_replication(tableArn=table_arn, versionToken=current)

    ctx.on_cleanup(_delete_table_repl)

    assert bucket_repl_version and table_repl_version, (
        f"expected both PUT calls to return a versionToken, got "
        f"bucket={bucket_repl_version!r} table={table_repl_version!r}"
    )

    # Poll for the destination to reach a terminal replication status. The wire
    # enum is lowercase ("pending" | "completed" | "failed") even though the docs
    # and console render it capitalized for humans.
    status_resp = _poll_until(
        lambda: s3tables.get_table_replication_status(tableArn=table_arn),
        lambda r: any(d["replicationStatus"] in ("completed", "failed") for d in r.get("destinations", [])),
        timeout_s=600.0,
        interval_s=15.0,
    )
    dest_status = status_resp["destinations"][0]
    assert dest_status["replicationStatus"] == "completed", (
        f"replication did not complete: {dest_status['replicationStatus']} "
        f"({dest_status.get('failureMessage')})"
    )

    # Independent read AT THE DESTINATION: the replicated table must actually exist
    # in the destination bucket under the same namespace/name, and its ARN must
    # match what the source's own status call claimed -- not merely trust the
    # source-side status report.
    dst_table = s3tables.get_table(tableBucketARN=dst_arn, namespace=ns_name, name=table_name)
    assert dst_table["tableARN"] == dest_status["destinationTableArn"], (
        f"destination table ARN mismatch: status reported "
        f"{dest_status['destinationTableArn']!r}, GetTable at the destination returned "
        f"{dst_table['tableARN']!r}"
    )
    assert dst_table["namespace"] == [ns_name] and dst_table["name"] == table_name, (
        f"replicated table identity mismatch: expected namespace={[ns_name]!r} name={table_name!r}, "
        f"got namespace={dst_table['namespace']!r} name={dst_table['name']!r}"
    )


def _delete_if_present(fn) -> None:
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "NotFoundException":
            raise


def _retry_on_role_propagation(fn, timeout_s: float = 120.0, interval_s: float = 5.0):
    """IAM roles are eventually consistent; S3 Tables may reject the role with
    AccessDenied/Forbidden until the trust + permissions policy propagates."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code not in ("AccessDeniedException", "ForbiddenException"):
                raise
            last_err = e
            time.sleep(interval_s)
    raise AssertionError(f"role never became usable within {timeout_s}s: {last_err}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
