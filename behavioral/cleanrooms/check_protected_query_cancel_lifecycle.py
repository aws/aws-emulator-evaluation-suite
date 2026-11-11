"""protected-query-cancel-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "protected-query-cancel-lifecycle"
GROUP = "state-machine"
SERVICES = ["cleanrooms"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A protected query cancelled right after submission reaches CANCELLED and writes no result object;
    cancelling it again returns 200 with status CANCELLED, and GetProtectedQuery still reads CANCELLED."""
    s3 = ctx.client("s3")
    glue = ctx.client("glue")
    iam = ctx.client("iam")
    cr = ctx.client("cleanrooms")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    bucket = ctx.unique_name("sim2real-cr-").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket)
    results_bucket = ctx.unique_name("sim2real-cr-out-").lower().replace("_", "-")
    _create_bucket(ctx, s3, results_bucket)

    key = "data/rows.csv"
    csv_body = "id,value\n1,10\n2,20\n3,30\n"
    s3.put_object(Bucket=bucket, Key=key, Body=csv_body.encode())

    db_name = ctx.unique_name("sim2real_cr_db_").replace("-", "_")
    table_name = "rows_table"
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "TableType": "EXTERNAL_TABLE",
            "Parameters": {"classification": "csv", "skip.header.line.count": "1"},
            "StorageDescriptor": {
                "Columns": [
                    {"Name": "id", "Type": "string"},
                    {"Name": "value", "Type": "string"},
                ],
                "Location": f"s3://{bucket}/data/",
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                "SerdeInfo": {
                    "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                    "Parameters": {"field.delim": ","},
                },
            },
        },
    )

    role_name = ctx.unique_name("sim2real-cr-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "cleanrooms.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = "sim2real-cr-inline"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["glue:GetTable", "glue:GetDatabase", "glue:GetPartitions", "glue:GetTables"],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:ListBucket", "s3:GetBucketLocation"],
                "Resource": [f"arn:aws:s3:::{results_bucket}", f"arn:aws:s3:::{results_bucket}/*"],
            },
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    collab = cr.create_collaboration(
        name=ctx.unique_name("sim2real-cr-collab-"),
        description="behavioral fidelity check",
        members=[],
        creatorMemberAbilities=["CAN_QUERY", "CAN_RECEIVE_RESULTS"],
        creatorDisplayName="creator",
        queryLogStatus="DISABLED",
        tags={"sim2real-check": CHECK},
    )["collaboration"]
    collab_id = collab["id"]
    membership_ids = []
    ctx.on_cleanup(lambda: _delete_collaboration_then_memberships(cr, collab_id, membership_ids))

    membership = _create_membership_with_retry(
        cr, collab_id, results_bucket, role_arn, tags={"sim2real-check": CHECK}
    )
    membership_id = membership["id"]
    membership_ids.append(membership_id)

    configured_table = cr.create_configured_table(
        name=ctx.unique_name("sim2real-cr-table-"),
        tableReference={"glue": {"tableName": table_name, "databaseName": db_name}},
        allowedColumns=["id", "value"],
        analysisMethod="DIRECT_QUERY",
    )["configuredTable"]
    table_id = configured_table["id"]
    ctx.on_cleanup(lambda: cr.delete_configured_table(configuredTableIdentifier=table_id))

    cr.create_configured_table_analysis_rule(
        configuredTableIdentifier=table_id,
        analysisRuleType="CUSTOM",
        analysisRulePolicy={
            "v1": {"custom": {"allowedAnalyses": ["ANY_QUERY"], "allowedAnalysisProviders": [account_id]}}
        },
    )

    assoc_name = "rows_assoc"
    association = _create_association_with_retry(
        cr,
        name=assoc_name,
        membershipIdentifier=membership_id,
        configuredTableIdentifier=table_id,
        roleArn=role_arn,
    )
    assoc_id = association["id"]
    ctx.on_cleanup(lambda: cr.delete_configured_table_association(
        configuredTableAssociationIdentifier=assoc_id, membershipIdentifier=membership_id))

    cr.create_configured_table_association_analysis_rule(
        membershipIdentifier=membership_id,
        configuredTableAssociationIdentifier=assoc_id,
        analysisRuleType="CUSTOM",
        analysisRulePolicy={"v1": {"custom": {"allowedResultReceivers": [account_id]}}},
    )

    query_string = f"SELECT id, value FROM {assoc_name}"
    protected_query = _start_query_with_retry(cr, membership_id, query_string)
    query_id = protected_query["id"]

    # Cancel immediately, before the query's compute cluster has had time to spin
    # up and finish -- this is the only window in which CANCELLED (rather than a
    # race against SUCCESS) is the reliable outcome.
    cr.update_protected_query(
        membershipIdentifier=membership_id, protectedQueryIdentifier=query_id, targetStatus="CANCELLED"
    )

    final = _poll_query_status(cr, membership_id, query_id, {"CANCELLED", "CANCELLING"}, timeout_s=120)
    final = _poll_query_status(cr, membership_id, query_id, {"CANCELLED"}, timeout_s=120, seed=final)
    assert final["status"] == "CANCELLED", f"expected CANCELLED, got {final['status']!r}"

    listing = s3.list_objects_v2(Bucket=results_bucket, Prefix="results/")
    assert listing.get("KeyCount", 0) == 0, "cancelled query must not have written a result object"

    recancel = cr.update_protected_query(
        membershipIdentifier=membership_id, protectedQueryIdentifier=query_id, targetStatus="CANCELLED"
    )["protectedQuery"]
    assert recancel["status"] == "CANCELLED", (
        f"expected re-cancelling a terminal query to be an idempotent no-op, got {recancel['status']!r}"
    )

    still = cr.get_protected_query(
        membershipIdentifier=membership_id, protectedQueryIdentifier=query_id
    )["protectedQuery"]
    assert still["status"] == "CANCELLED", "re-cancelling a terminal query must not change its status"


def _delete_collaboration_then_memberships(cr, collab_id, membership_ids):
    """The creator's ACTIVE membership cannot be deleted, so the collaboration goes first and
    each membership is deleted once it reads COLLABORATION_DELETED."""
    cr.delete_collaboration(collaborationIdentifier=collab_id)
    for membership_id in membership_ids:
        deadline = time.monotonic() + 60
        status = None
        while time.monotonic() < deadline:
            status = cr.get_membership(membershipIdentifier=membership_id)["membership"]["status"]
            if status == "COLLABORATION_DELETED":
                break
            time.sleep(2)
        else:
            raise AssertionError(
                f"membership {membership_id} never reached COLLABORATION_DELETED: {status}"
            )
        cr.delete_membership(membershipIdentifier=membership_id)


def _create_bucket(ctx, s3, name: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))


def _empty_and_delete_bucket(s3, name: str) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=name):
        objs = page.get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
    s3.delete_bucket(Bucket=name)


def _create_membership_with_retry(cr, collab_id, bucket, role_arn, *, tags, timeout_s: float = 90.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return cr.create_membership(
                collaborationIdentifier=collab_id,
                queryLogStatus="DISABLED",
                defaultResultConfiguration={
                    "outputConfiguration": {
                        "s3": {"bucket": bucket, "keyPrefix": "results/", "resultFormat": "CSV"}
                    },
                    "roleArn": role_arn,
                },
                tags=tags,
            )["membership"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "AccessDeniedException":
                last_exc = exc
                time.sleep(5)
                continue
            raise
    raise AssertionError(f"CreateMembership never succeeded, likely IAM propagation delay: {last_exc}")


def _create_association_with_retry(cr, timeout_s: float = 90.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return cr.create_configured_table_association(**kwargs)["configuredTableAssociation"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ValidationException":
                last_exc = exc
                time.sleep(5)
                continue
            raise
    raise AssertionError(f"association never created, likely IAM propagation delay: {last_exc}")


def _start_query_with_retry(cr, membership_id: str, query_string: str, timeout_s: float = 90.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return cr.start_protected_query(
                type="SQL",
                membershipIdentifier=membership_id,
                sqlParameters={"queryString": query_string},
            )["protectedQuery"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException"):
                last_exc = exc
                time.sleep(5)
                continue
            raise
    raise AssertionError(f"StartProtectedQuery never succeeded, likely IAM propagation delay: {last_exc}")


def _poll_query_status(cr, membership_id, query_id, acceptable, timeout_s=120.0, seed=None):
    deadline = time.monotonic() + timeout_s
    pq = seed
    while time.monotonic() < deadline:
        pq = cr.get_protected_query(
            membershipIdentifier=membership_id, protectedQueryIdentifier=query_id
        )["protectedQuery"]
        if pq["status"] in acceptable:
            return pq
        time.sleep(3)
    raise AssertionError(f"query never reached one of {acceptable}, last saw {pq}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
