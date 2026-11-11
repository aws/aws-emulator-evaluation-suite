"""matching-workflow-create-get-update-roundtrip."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "matching-workflow-create-get-update-roundtrip"
GROUP = "control-plane"
SERVICES = ["entityresolution"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateMatchingWorkflow persists resolutionTechniques/roleArn; UpdateMatchingWorkflow
    changes the stored description and rule set, visible on the next GetMatchingWorkflow."""
    er = ctx.client("entityresolution")
    role_arn = _create_passive_role(ctx)
    schema_name = _create_schema(ctx, er)
    workflow_name = ctx.unique_name("sim2real-er-wf-")
    bucket = ctx.unique_name("sim2real-er-out-").lower()
    source_arn = _create_glue_table(ctx, ["id", "email", "name"])

    _create_workflow_with_retry(
        er,
        workflowName=workflow_name,
        description="initial description",
        inputSourceConfig=[{"inputSourceARN": source_arn, "schemaName": schema_name}],
        outputSourceConfig=[{"outputS3Path": f"s3://{bucket}/out", "output": []}],
        resolutionTechniques={
            "resolutionType": "RULE_MATCHING",
            "ruleBasedProperties": {
                "attributeMatchingModel": "ONE_TO_ONE",
                "matchPurpose": "IDENTIFIER_GENERATION",
                "rules": [{"ruleName": "emailRule", "matchingKeys": ["email"]}],
            },
        },
        roleArn=role_arn,
        tags={"sim2real-behav": CHECK},
    )
    ctx.on_cleanup(lambda: _safe_delete_workflow(er, workflow_name))

    got = er.get_matching_workflow(workflowName=workflow_name)
    assert got["description"] == "initial description", (
        f"expected description 'initial description', got {got['description']!r}"
    )
    assert got["roleArn"] == role_arn, f"expected roleArn {role_arn!r} persisted, got {got['roleArn']!r}"
    rbp = got["resolutionTechniques"]
    assert rbp["resolutionType"] == "RULE_MATCHING", (
        f"expected resolutionType RULE_MATCHING, got {rbp['resolutionType']!r}"
    )
    assert rbp["ruleBasedProperties"]["attributeMatchingModel"] == "ONE_TO_ONE", (
        f"expected attributeMatchingModel ONE_TO_ONE, got "
        f"{rbp['ruleBasedProperties']['attributeMatchingModel']!r}"
    )
    assert rbp["ruleBasedProperties"]["matchPurpose"] == "IDENTIFIER_GENERATION", (
        f"expected matchPurpose IDENTIFIER_GENERATION, got {rbp['ruleBasedProperties']['matchPurpose']!r}"
    )

    er.update_matching_workflow(
        workflowName=workflow_name,
        description="updated description",
        inputSourceConfig=[{"inputSourceARN": source_arn, "schemaName": schema_name}],
        outputSourceConfig=[{"outputS3Path": f"s3://{bucket}/out", "output": []}],
        resolutionTechniques={
            "resolutionType": "RULE_MATCHING",
            "ruleBasedProperties": {
                "attributeMatchingModel": "ONE_TO_ONE",
                "matchPurpose": "IDENTIFIER_GENERATION",
                "rules": [
                    {"ruleName": "emailRule", "matchingKeys": ["email"]},
                    {"ruleName": "nameRule", "matchingKeys": ["name"]},
                ],
            },
        },
        roleArn=role_arn,
    )
    updated = er.get_matching_workflow(workflowName=workflow_name)
    assert updated["description"] == "updated description", (
        f"expected description 'updated description', got {updated['description']!r}"
    )
    assert updated["roleArn"] == role_arn, (
        f"expected roleArn {role_arn!r} still persisted after update, got {updated['roleArn']!r}"
    )
    rule_names = {r["ruleName"] for r in updated["resolutionTechniques"]["ruleBasedProperties"]["rules"]}
    assert rule_names == {"emailRule", "nameRule"}, (
        f"expected rule set {{'emailRule', 'nameRule'}} after update, got {rule_names!r}"
    )


def _create_workflow_with_retry(er, timeout_s=120.0, **kwargs):
    """CreateMatchingWorkflow synchronously verifies it can assume roleArn AND that the Glue
    Catalog table it references is readable. Both a just-created IAM role and a just-created
    Glue table can lag behind eventual consistency, so retry on those specific errors for a
    bounded window instead of failing fast."""
    import time as _time

    deadline = _time.monotonic() + timeout_s
    last_err = None
    while _time.monotonic() < deadline:
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
                _time.sleep(3)
                continue
            raise
    raise AssertionError(f"create_matching_workflow never succeeded (IAM/Glue propagation?): {last_err}")


def _create_glue_table(ctx, columns, suffix="tbl"):
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-er-glue-").lower()
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-behav", "Value": CHECK}]})

    db_name = ctx.unique_name("sim2real_er_db_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real-behav": CHECK})
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


def _create_schema(ctx, er):
    name = ctx.unique_name("sim2real-er-schema-")
    er.create_schema_mapping(
        schemaName=name,
        mappedInputFields=[
            {"fieldName": "id", "type": "UNIQUE_ID"},
            {"fieldName": "email", "type": "EMAIL_ADDRESS", "matchKey": "email"},
            {"fieldName": "name", "type": "NAME", "matchKey": "name"},
        ],
        tags={"sim2real-behav": CHECK},
    )
    ctx.on_cleanup(lambda: _safe_delete_schema(er, name))
    return name


def _create_passive_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-er-role-")
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_role(iam, role_name))
    access_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "glue:GetTable",
                    "glue:GetDatabase",
                    "glue:GetPartitions",
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:ListBucket",
                    "s3:GetBucketLocation",
                ],
                "Resource": "*",
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="er-access", PolicyDocument=json.dumps(access_policy)
    )
    ctx.on_cleanup(lambda: _safe_delete_role_policy(iam, role_name))
    return role["Role"]["Arn"]


def _safe_delete_role_policy(iam, role_name):
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName="er-access")
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
