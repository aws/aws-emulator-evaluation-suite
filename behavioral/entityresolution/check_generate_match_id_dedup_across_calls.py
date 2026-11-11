"""generate-match-id-dedup-across-calls."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "generate-match-id-dedup-across-calls"
GROUP = "data-plane"
SERVICES = ["entityresolution"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GenerateMatchId on a rule-based workflow returns the same matchId for two records that share an email
    match key and a different matchId for an unrelated third record, with no batch job run."""
    er = ctx.client("entityresolution")
    bucket = _create_output_bucket(ctx)
    role_arn = _create_er_role(ctx, bucket)
    schema_name = ctx.unique_name("sim2real-er-rt-schema-")
    er.create_schema_mapping(
        schemaName=schema_name,
        mappedInputFields=[
            {"fieldName": "id", "type": "UNIQUE_ID"},
            {"fieldName": "email", "type": "EMAIL_ADDRESS", "matchKey": "email"},
        ],
        tags={"sim2real": "true"},
    )
    ctx.on_cleanup(lambda: _safe_delete_schema(er, schema_name))

    workflow_name = ctx.unique_name("sim2real-er-rt-wf-")
    source_arn = _create_glue_table(ctx, bucket, ["id", "email"])
    _create_workflow_with_retry(
        er,
        workflowName=workflow_name,
        inputSourceConfig=[{"inputSourceARN": source_arn, "schemaName": schema_name}],
        outputSourceConfig=[{"outputS3Path": f"s3://{bucket}/output", "output": []}],
        resolutionTechniques={
            "resolutionType": "RULE_MATCHING",
            "ruleBasedProperties": {
                "attributeMatchingModel": "ONE_TO_ONE",
                "matchPurpose": "IDENTIFIER_GENERATION",
                "rules": [{"ruleName": "emailRule", "matchingKeys": ["email"]}],
            },
        },
        incrementalRunConfig={"incrementalRunType": "IMMEDIATE"},
        roleArn=role_arn,
        tags={"sim2real": "true"},
    )
    ctx.on_cleanup(lambda: _safe_delete_workflow(er, workflow_name))

    def _generate(unique_id, email):
        return _poll_generate_match_id(er, workflow_name, source_arn, unique_id, email)

    first = _generate("rec-a", "dup@example.com")
    match_id_1 = first["matchGroups"][0]["matchId"]

    second = _generate("rec-b", "dup@example.com")
    match_id_2 = second["matchGroups"][0]["matchId"]
    assert match_id_2 == match_id_1, "records sharing the email match key must share a matchId"

    third = _generate("rec-c", "unrelated@example.com")
    match_id_3 = third["matchGroups"][0]["matchId"]
    assert match_id_3 != match_id_1, "an unrelated record must not share the existing matchId"


def _create_workflow_with_retry(er, timeout_s=240.0, **kwargs):
    """CreateMatchingWorkflow synchronously verifies it can assume roleArn AND that the Glue
    Catalog table it references is readable. Both a just-created IAM role and a just-created
    Glue table can lag behind eventual consistency, so retry on those specific errors for a
    bounded window instead of failing fast."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return er.create_matching_workflow(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "")
            retryable = code == "AccessDeniedException" or (
                code == "ValidationException" and "glue" in msg.lower()
            )
            if retryable:
                last_err = e
                time.sleep(3)
                continue
            raise
    raise AssertionError(f"create_matching_workflow never succeeded (IAM/Glue propagation?): {last_err}")


def _create_glue_table(ctx, bucket, columns, suffix="tbl"):
    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real_er_db_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: _safe_delete_database(glue, db_name))

    table_name = ctx.unique_name(f"sim2real_er_{suffix}_").replace("-", "_")
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "StorageDescriptor": {
                "Columns": [{"Name": c, "Type": "string"} for c in columns],
                "Location": f"s3://{bucket}/{table_name}/",
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                "SerdeInfo": {"SerializationLibrary": "org.apache.hadoop.hive.serde2.OpenCSVSerde"},
            },
            "TableType": "EXTERNAL_TABLE",
        },
    )
    ctx.on_cleanup(lambda: _safe_delete_table(glue, db_name, table_name))
    account = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:glue:{ctx.region}:{account}:table/{db_name}/{table_name}"


def _safe_delete_database(glue, db_name):
    try:
        glue.delete_database(Name=db_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _safe_delete_table(glue, db_name, table_name):
    try:
        glue.delete_table(DatabaseName=db_name, Name=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _poll_generate_match_id(er, workflow_name, source_arn, unique_id, email, timeout_s=90.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return er.generate_match_id(
                workflowName=workflow_name,
                records=[
                    {
                        "inputSourceARN": source_arn,
                        "uniqueId": unique_id,
                        "recordAttributeMap": {"email": email},
                    }
                ],
            )
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "AccessDeniedException":
                last_err = e
                time.sleep(3)
                continue
            raise
    raise AssertionError(f"generate_match_id never succeeded (IAM propagation?): {last_err}")


def _create_output_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-er-rt-out-").lower()
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name):
    s3 = ctx.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _create_er_role(ctx, bucket_name):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-er-rt-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "entityresolution.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_delete_role(iam, role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket", "s3:GetBucketLocation"],
                "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["glue:GetTable", "glue:GetDatabase", "glue:GetPartitions"],
                "Resource": "*",
            },
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="er-s3-access", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: _safe_delete_role_policy(iam, role_name))
    return role_arn


def _safe_delete_role_policy(iam, role_name):
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName="er-s3-access")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _safe_delete_role(iam, role_name):
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _safe_delete_schema(er, name):
    try:
        er.delete_schema_mapping(schemaName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_workflow(er, name):
    try:
        er.delete_matching_workflow(workflowName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
