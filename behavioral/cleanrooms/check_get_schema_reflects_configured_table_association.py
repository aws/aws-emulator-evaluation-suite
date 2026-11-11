"""get-schema-reflects-configured-table-association."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-schema-reflects-configured-table-association"
GROUP = "state"
SERVICES = ["cleanrooms"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Once a configured table association exists in a collaboration, GetSchema
    exposes it under the association's name with the real column list and
    analysis rule type -- not just an echo of the CreateConfiguredTable request."""
    glue = ctx.client("glue")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    cr = ctx.client("cleanrooms")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    bucket = _create_data_bucket(ctx, s3)
    db_name, table_name = _create_glue_table(ctx, glue, bucket)
    role_arn = _create_trusted_role(ctx, iam, ctx.region, account_id, db_name, table_name, bucket)

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
        analysisRuleType="LIST",
        analysisRulePolicy={"v1": {"list": {"joinColumns": ["id"], "listColumns": ["value"]}}},
    )

    collab_id = cr.create_collaboration(
        name=ctx.unique_name("sim2real-cr-collab-"),
        description="behavioral fidelity check",
        members=[],
        creatorMemberAbilities=["CAN_QUERY", "CAN_RECEIVE_RESULTS"],
        creatorDisplayName="creator",
        queryLogStatus="DISABLED",
    )["collaboration"]["id"]
    ctx.on_cleanup(lambda: cr.delete_collaboration(collaborationIdentifier=collab_id))

    membership_id = cr.create_membership(
        collaborationIdentifier=collab_id, queryLogStatus="DISABLED"
    )["membership"]["id"]
    # No membership teardown: AWS refuses DeleteMembership for the creator while it is ACTIVE;
    # the collaboration teardown removes it.

    assoc_name = "schema_check_assoc"
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
        analysisRuleType="LIST",
        analysisRulePolicy={"v1": {"list": {"allowedResultReceivers": [account_id]}}},
    )

    schema = cr.get_schema(collaborationIdentifier=collab_id, name=assoc_name)["schema"]
    assert schema["name"] == assoc_name, f"expected schema name {assoc_name!r}, got {schema['name']!r}"
    assert schema["analysisMethod"] == "DIRECT_QUERY", (
        f"expected analysisMethod DIRECT_QUERY, got {schema['analysisMethod']!r}"
    )
    assert schema["analysisRuleTypes"] == ["LIST"], (
        f"expected analysisRuleTypes ['LIST'], got {schema['analysisRuleTypes']!r}"
    )
    column_names = sorted(c["name"] for c in schema["columns"])
    assert column_names == ["id", "value"], f"expected columns ['id', 'value'], got {column_names!r}"


# ===== helpers =====

def _create_data_bucket(ctx, s3) -> str:
    bucket = ctx.unique_name("sim2real-cr-data-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_glue_table(ctx, glue, bucket):
    db_name = ctx.unique_name("sim2real_cr_db_").replace("-", "_")
    table_name = "cr_table"
    location = f"s3://{bucket}/{db_name}/"
    ctx.client("s3").put_object(Bucket=bucket, Key=f"{db_name}/data.csv", Body=b"1,alpha\n2,beta\n")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "TableType": "EXTERNAL_TABLE",
            "StorageDescriptor": {
                "Columns": [{"Name": "id", "Type": "string"}, {"Name": "value", "Type": "string"}],
                "Location": location,
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


def _create_trusted_role(ctx, iam, region, account_id, db_name, table_name, bucket):
    role_name = ctx.unique_name("sim2real-cr-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "cleanrooms.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    # CreateConfiguredTableAssociation checks the role's Glue and S3 read access synchronously
    # (AccessDeniedException "Insufficient permissions to access table ..."; ValidationException
    # "Bucket ... does not exist" on every attempt) -- a trust policy alone is not enough.
    data_access = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "glue:GetTable",
                    "glue:GetTableVersion",
                    "glue:GetTableVersions",
                    "glue:GetPartitions",
                    "glue:GetPartition",
                    "glue:GetDatabase",
                    "glue:GetDatabases",
                ],
                "Resource": [
                    f"arn:aws:glue:{region}:{account_id}:catalog",
                    f"arn:aws:glue:{region}:{account_id}:database/{db_name}",
                    f"arn:aws:glue:{region}:{account_id}:table/{db_name}/{table_name}",
                ],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:GetBucketLocation", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            },
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="glue-table-read", PolicyDocument=json.dumps(data_access)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="glue-table-read"))
    return arn


def _create_association_with_retry(cr, timeout_s: float = 240.0, **kwargs):
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
