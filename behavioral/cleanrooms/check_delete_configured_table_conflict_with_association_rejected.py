"""delete-configured-table-conflict-with-association-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-configured-table-conflict-with-association-rejected"
GROUP = "overly-permissive"
SERVICES = ["cleanrooms"]


@tags("axis:happy-path", "cap:c1", "plane:control")
def run(ctx) -> None:
    """DeleteConfiguredTable on a table with a live configured table association succeeds: Clean Rooms
    does not guard the table; a second delete answers ResourceNotFoundException "No such table '<id>'", and
    deleting its rule answers "No such analysis rule with configuredTableId: <id> and type AGGREGATION"."""
    glue = ctx.client("glue")
    iam = ctx.client("iam")
    cr = ctx.client("cleanrooms")
    s3 = ctx.client("s3")

    db_name, table_name = _create_glue_table(ctx, glue, s3)
    role_arn = _create_trusted_role(ctx, iam)

    configured_table = cr.create_configured_table(
        name=ctx.unique_name("sim2real-cr-table-"),
        tableReference={"glue": {"tableName": table_name, "databaseName": db_name}},
        allowedColumns=["id", "value"],
        analysisMethod="DIRECT_QUERY",
        tags={"sim2real": CHECK},
    )["configuredTable"]
    table_id = configured_table["id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: cr.delete_configured_table(configuredTableIdentifier=table_id)))

    cr.create_configured_table_analysis_rule(
        configuredTableIdentifier=table_id,
        analysisRuleType="AGGREGATION",
        analysisRulePolicy={
            "v1": {
                "aggregation": {
                    "aggregateColumns": [{"columnNames": ["value"], "function": "COUNT"}],
                    "joinColumns": ["id"],
                    "dimensionColumns": [],
                    "outputConstraints": [{"columnName": "value", "minimum": 2, "type": "COUNT_DISTINCT"}],
                    "scalarFunctions": [],
                }
            }
        },
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: cr.delete_configured_table_analysis_rule(
        configuredTableIdentifier=table_id, analysisRuleType="AGGREGATION")))

    collab_id = cr.create_collaboration(
        name=ctx.unique_name("sim2real-cr-collab-"),
        description="behavioral fidelity check",
        members=[],
        creatorMemberAbilities=["CAN_QUERY", "CAN_RECEIVE_RESULTS"],
        creatorDisplayName="creator",
        queryLogStatus="DISABLED",
        tags={"sim2real": CHECK},
    )["collaboration"]["id"]
    ctx.on_cleanup(lambda: cr.delete_collaboration(collaborationIdentifier=collab_id))

    membership_id = cr.create_membership(
        collaborationIdentifier=collab_id, queryLogStatus="DISABLED", tags={"sim2real": CHECK},
    )["membership"]["id"]
    # The creator's membership cannot be deleted while it is ACTIVE; DeleteCollaboration removes it.

    association = _create_association_with_retry(
        cr,
        name="cr_assoc",
        membershipIdentifier=membership_id,
        configuredTableIdentifier=table_id,
        roleArn=role_arn,
        tags={"sim2real": CHECK},
    )
    assoc_id = association["id"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: cr.delete_configured_table_association(
        configuredTableAssociationIdentifier=assoc_id, membershipIdentifier=membership_id)))

    # The live association does not block the delete.
    cr.delete_configured_table(configuredTableIdentifier=table_id)

    gone = _error(lambda: cr.delete_configured_table(configuredTableIdentifier=table_id))
    assert gone == ("ResourceNotFoundException", f"No such table '{table_id}'"), (
        f"expected the configured table to be gone after the accepted delete, got {gone!r}"
    )
    # The table's analysis rule went with it.
    rule_gone = _error(lambda: cr.delete_configured_table_analysis_rule(
        configuredTableIdentifier=table_id, analysisRuleType="AGGREGATION"))
    expected = ("ResourceNotFoundException",
                f"No such analysis rule with configuredTableId: {table_id} and type AGGREGATION")
    assert rule_gone == expected, (
        f"expected the analysis rule to be gone with its table: {expected!r}, got {rule_gone!r}"
    )


def _create_glue_table(ctx, glue, s3):
    db_name = ctx.unique_name("sim2real_cr_db_").replace("-", "_")
    table_name = "cr_table"
    bucket = ctx.unique_name("sim2real-cr-").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket)
    s3.put_object(Bucket=bucket, Key=f"{db_name}/data.csv", Body=b"id,value\n1,a\n2,b\n")

    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": {
                "Columns": [{"Name": "id", "Type": "string"}, {"Name": "value", "Type": "string"}],
                "Location": f"s3://{bucket}/{db_name}/",
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                "SerdeInfo": {
                    "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                    "Parameters": {"field.delim": ","},
                },
            },
        },
    )
    return db_name, table_name


def _create_bucket(ctx, s3, name: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))


def _empty_and_delete_bucket(s3, name: str) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=name):
        objs = page.get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
    s3.delete_bucket(Bucket=name)


def _create_trusted_role(ctx, iam):
    role_name = ctx.unique_name("sim2real-cr-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "cleanrooms.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    # CreateConfiguredTableAssociation deterministically rejects a role that can only be
    # assumed -- it also validates the role can read the underlying Glue table and its S3
    # location (AccessDeniedException: "Insufficient permissions to access table ..."), so a
    # bare trust policy is not enough.
    access_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["glue:GetTable", "glue:GetDatabase", "glue:GetPartitions"],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:GetBucketLocation", "s3:ListBucket"],
                "Resource": "*",
            },
        ],
    }
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-cr-table-access",
        PolicyDocument=json.dumps(access_policy),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-cr-table-access"))
    return arn


def _create_association_with_retry(cr, timeout_s: float = 480.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return cr.create_configured_table_association(**kwargs)["configuredTableAssociation"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("ValidationException", "AccessDeniedException"):
                last_exc = exc
                time.sleep(2)
                continue
            raise
    raise AssertionError(f"association never created, likely IAM propagation delay: {last_exc}")


def _error(fn):
    """(code, message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
