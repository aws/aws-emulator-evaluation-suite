"""protected-query-list-rule-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "protected-query-list-rule-round-trip"
GROUP = "data-plane"
SERVICES = ["cleanrooms"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Full Clean Rooms data-plane round trip: a Glue-backed configured table with a
    LIST analysis rule is queried via StartProtectedQuery, the query is polled to
    SUCCESS, and the CSV result that lands in S3 contains the real source rows."""
    s3 = ctx.client("s3")
    glue = ctx.client("glue")
    iam = ctx.client("iam")
    cr = ctx.client("cleanrooms")

    # Clean Rooms rejects a query whose result location is the same bucket as the
    # queried data (ValidationException: "You can't use this membership to query
    # data that is located in the same S3 bucket as the result location"), so the
    # source data and the query output need distinct buckets.
    data_bucket = ctx.unique_name("sim2real-cr-data-").lower().replace("_", "-")
    results_bucket = ctx.unique_name("sim2real-cr-res-").lower().replace("_", "-")
    _create_bucket(ctx, s3, data_bucket)
    _create_bucket(ctx, s3, results_bucket)

    key = "data/rows.csv"
    csv_body = "id,value,joinkey\n1,10,jk1\n2,20,jk2\n3,30,jk3\n"
    s3.put_object(Bucket=data_bucket, Key=key, Body=csv_body.encode())

    labels_key = "labels/labels.csv"
    labels_csv_body = "joinkey,label\njk1,A\njk2,B\njk3,C\n"
    s3.put_object(Bucket=data_bucket, Key=labels_key, Body=labels_csv_body.encode())

    db_name = ctx.unique_name("sim2real_cr_db_").replace("-", "_")
    table_name = "rows_table"
    labels_table_name = "labels_table"
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    def _csv_table_input(name: str, columns: list[dict], location: str) -> dict:
        return {
            "Name": name,
            "TableType": "EXTERNAL_TABLE",
            "Parameters": {"classification": "csv", "skip.header.line.count": "1"},
            "StorageDescriptor": {
                "Columns": columns,
                "Location": location,
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                "SerdeInfo": {
                    "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                    "Parameters": {"field.delim": ","},
                },
            },
        }

    glue.create_table(
        DatabaseName=db_name,
        TableInput=_csv_table_input(
            table_name,
            [
                {"Name": "id", "Type": "string"},
                {"Name": "value", "Type": "string"},
                {"Name": "joinkey", "Type": "string"},
            ],
            f"s3://{data_bucket}/data/",
        ),
    )
    glue.create_table(
        DatabaseName=db_name,
        TableInput=_csv_table_input(
            labels_table_name,
            [
                {"Name": "joinkey", "Type": "string"},
                {"Name": "label", "Type": "string"},
            ],
            f"s3://{data_bucket}/labels/",
        ),
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
                "Resource": [f"arn:aws:s3:::{data_bucket}", f"arn:aws:s3:::{data_bucket}/*"],
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
        tags={"sim2real": CHECK},
    )["collaboration"]
    collab_id = collab["id"]
    ctx.on_cleanup(lambda: cr.delete_collaboration(collaborationIdentifier=collab_id))

    membership = _create_membership_with_retry(
        cr,
        collaborationIdentifier=collab_id,
        queryLogStatus="DISABLED",
        defaultResultConfiguration={
            "outputConfiguration": {
                "s3": {"bucket": results_bucket, "keyPrefix": "results/", "resultFormat": "CSV"}
            },
            "roleArn": role_arn,
        },
        tags={"sim2real": CHECK},
    )
    membership_id = membership["id"]
    ctx.on_cleanup(lambda: cr.delete_membership(membershipIdentifier=membership_id))

    account_id = ctx.client("sts").get_caller_identity()["Account"]

    def _configure_and_associate(
        glue_table_name: str, join_columns: list[str], list_columns: list[str], allowed_columns: list[str], assoc_name: str
    ) -> str:
        configured_table = cr.create_configured_table(
            name=ctx.unique_name("sim2real-cr-table-"),
            tableReference={"glue": {"tableName": glue_table_name, "databaseName": db_name}},
            allowedColumns=allowed_columns,
            analysisMethod="DIRECT_QUERY",
            tags={"sim2real": CHECK},
        )["configuredTable"]
        table_id = configured_table["id"]
        ctx.on_cleanup(lambda: cr.delete_configured_table(configuredTableIdentifier=table_id))

        cr.create_configured_table_analysis_rule(
            configuredTableIdentifier=table_id,
            analysisRuleType="LIST",
            # AWS rejects a column used as both a join column and a list column
            # (ValidationException: "List columns: [...] cannot be used a join columns"),
            # so the join column is always disjoint from the listed columns.
            analysisRulePolicy={"v1": {"list": {"joinColumns": join_columns, "listColumns": list_columns}}},
        )

        association = _create_association_with_retry(
            ctx,
            cr,
            name=assoc_name,
            membershipIdentifier=membership_id,
            configuredTableIdentifier=table_id,
            roleArn=role_arn,
            tags={"sim2real": CHECK},
        )
        assoc_id = association["id"]
        ctx.on_cleanup(lambda: cr.delete_configured_table_association(
            configuredTableAssociationIdentifier=assoc_id, membershipIdentifier=membership_id))

        cr.create_configured_table_association_analysis_rule(
            membershipIdentifier=membership_id,
            configuredTableAssociationIdentifier=assoc_id,
            analysisRuleType="LIST",
            analysisRulePolicy={"v1": {"list": {"allowedResultReceivers": [account_id]}}},
        )
        return assoc_name

    rows_assoc = _configure_and_associate(table_name, ["joinkey"], ["id", "value"], ["id", "value", "joinkey"], "rows_assoc")
    labels_assoc = _configure_and_associate(labels_table_name, ["joinkey"], ["label"], ["joinkey", "label"], "labels_assoc")

    # A LIST (or aggregation) analysis rule requires a join to another
    # collaborator table (QUERY_FAILED otherwise: "join to collaborator table
    # required"), requires SELECT DISTINCT ("DISTINCT quantifier missing from
    # SELECT expression"), and forbids ORDER BY ("ORDER_BY are not allowed by
    # list analysis rule(s)").
    query_string = (
        f"SELECT DISTINCT {rows_assoc}.id, {rows_assoc}.value, {labels_assoc}.label "
        f"FROM {rows_assoc} JOIN {labels_assoc} ON {rows_assoc}.joinkey = {labels_assoc}.joinkey"
    )
    protected_query = _start_query_with_retry(cr, membership_id, query_string)
    query_id = protected_query["id"]

    final = _poll_query_terminal(cr, membership_id, query_id, timeout_s=300)
    assert final["status"] == "SUCCESS", f"query ended in {final['status']}: {final.get('error')}"
    duration = final["statistics"]["totalDurationInMillis"]
    assert duration > 0, f"expected a positive totalDurationInMillis for a completed query, got {duration!r}"

    body = _read_results(s3, results_bucket, "results/")
    for expected_row in ("1,10,A", "2,20,B", "3,30,C"):
        assert expected_row in body, f"expected joined row {expected_row!r} missing from result body: {body!r}"


def _create_bucket(ctx, s3, name: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))


def _empty_and_delete_bucket(s3, name: str) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=name):
        objs = page.get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
    s3.delete_bucket(Bucket=name)


def _create_membership_with_retry(cr, timeout_s: float = 90.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return cr.create_membership(**kwargs)["membership"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDeniedException":
                last_exc = exc
                time.sleep(5)
                continue
            raise
    raise AssertionError(f"membership never created, likely IAM propagation delay: {last_exc}")


def _create_association_with_retry(ctx, cr, timeout_s: float = 90.0, **kwargs):
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


def _poll_query_terminal(cr, membership_id: str, query_id: str, timeout_s: float = 300.0):
    terminal = {"SUCCESS", "FAILED", "CANCELLED", "TIMED_OUT"}
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        pq = cr.get_protected_query(
            membershipIdentifier=membership_id, protectedQueryIdentifier=query_id
        )["protectedQuery"]
        if pq["status"] in terminal:
            return pq
        time.sleep(5)
    raise AssertionError("protected query did not reach a terminal state in time")


def _read_results(s3, bucket: str, prefix: str) -> str:
    paginator = s3.get_paginator("list_objects_v2")
    chunks = []
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for obj in page.get("Contents", []):
            chunks.append(s3.get_object(Bucket=bucket, Key=obj["Key"])["Body"].read().decode())
    if not chunks:
        raise AssertionError(f"no result objects found under s3://{bucket}/{prefix}")
    return "\n".join(chunks)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
