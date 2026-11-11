"""id-mapping-workflow-update-persists-changes."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "id-mapping-workflow-update-persists-changes"
GROUP = "state"
SERVICES = ["entityresolution"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateIdMappingWorkflow replaces the stored idMappingTechniques rules and description;
    the very next GetIdMappingWorkflow reflects the new rule set, not the original one."""
    er = ctx.client("entityresolution")
    schema_name = _create_schema(ctx, er)
    workflow_name = ctx.unique_name("sim2real-er-idmw-upd-")
    role_arn = _create_passive_role(ctx)
    source_table_arn = _create_glue_table(ctx, ["id", "email", "name"], suffix="source")
    target_table_arn = _create_glue_table(ctx, ["id", "email", "name"], suffix="target")
    # CreateIdMappingWorkflow rejects a bare Glue table ARN for either side with
    # ValidationException: a SOURCE/TARGET entry must be an entityresolution
    # matchingworkflow or idnamespace ARN that itself carries a rule definition
    # (idMappingTechniques.ruleDefinitionType == "SOURCE" requires the SOURCE side
    # to have rules defined in one). Bootstrap a MatchingWorkflow over each Glue table
    # purely to mint that ARN; neither is ever run.
    source_arn = _create_matching_workflow(ctx, er, role_arn, schema_name, source_table_arn)
    target_arn = _create_matching_workflow(ctx, er, role_arn, schema_name, target_table_arn)

    er.create_id_mapping_workflow(
        workflowName=workflow_name,
        description="v1",
        roleArn=role_arn,
        inputSourceConfig=[
            {"inputSourceARN": source_arn, "type": "SOURCE"},
            {"inputSourceARN": target_arn, "type": "TARGET"},
        ],
        idMappingTechniques={
            "idMappingType": "RULE_BASED",
            "ruleBasedProperties": {
                "attributeMatchingModel": "ONE_TO_ONE",
                "recordMatchingModel": "ONE_SOURCE_TO_ONE_TARGET",
                "ruleDefinitionType": "SOURCE",
                "rules": [{"ruleName": "emailRule", "matchingKeys": ["email"]}],
            },
        },
    )
    ctx.on_cleanup(lambda: _safe_delete_workflow(er, workflow_name))

    before = er.get_id_mapping_workflow(workflowName=workflow_name)
    assert before["description"] == "v1"
    assert [r["ruleName"] for r in before["idMappingTechniques"]["ruleBasedProperties"]["rules"]] == [
        "emailRule"
    ]

    er.update_id_mapping_workflow(
        workflowName=workflow_name,
        description="v2",
        roleArn=role_arn,
        inputSourceConfig=[
            {"inputSourceARN": source_arn, "type": "SOURCE"},
            {"inputSourceARN": target_arn, "type": "TARGET"},
        ],
        idMappingTechniques={
            "idMappingType": "RULE_BASED",
            "ruleBasedProperties": {
                "attributeMatchingModel": "ONE_TO_ONE",
                "recordMatchingModel": "ONE_SOURCE_TO_ONE_TARGET",
                "ruleDefinitionType": "SOURCE",
                "rules": [
                    {"ruleName": "emailRule", "matchingKeys": ["email"]},
                    {"ruleName": "nameRule", "matchingKeys": ["name"]},
                ],
            },
        },
    )

    after = er.get_id_mapping_workflow(workflowName=workflow_name)
    assert after["description"] == "v2"
    rule_names = {r["ruleName"] for r in after["idMappingTechniques"]["ruleBasedProperties"]["rules"]}
    assert rule_names == {"emailRule", "nameRule"}


def _create_matching_workflow(ctx, er, role_arn, schema_name, input_table_arn):
    s3 = ctx.client("s3")
    out_bucket = ctx.unique_name("sim2real-er-mwout-").lower()
    bucket_kwargs = {}
    if ctx.region != "us-east-1":
        bucket_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=out_bucket, **bucket_kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, out_bucket))

    name = ctx.unique_name("sim2real-er-mw-")
    kwargs = dict(
        workflowName=name,
        roleArn=role_arn,
        inputSourceConfig=[{"inputSourceARN": input_table_arn, "schemaName": schema_name}],
        outputSourceConfig=[
            {
                "outputS3Path": f"s3://{out_bucket}/output/",
                "output": [{"name": "id"}, {"name": "email"}, {"name": "name"}],
            }
        ],
        resolutionTechniques={
            "resolutionType": "RULE_MATCHING",
            "ruleBasedProperties": {
                "rules": [{"ruleName": "emailRule", "matchingKeys": ["email"]}],
                "attributeMatchingModel": "ONE_TO_ONE",
            },
        },
    )
    created = _create_matching_workflow_with_retry(er, **kwargs)
    ctx.on_cleanup(lambda: _safe_delete_matching_workflow(er, name))
    return created["workflowArn"]


def _create_matching_workflow_with_retry(er, timeout_s=60.0, **kwargs):
    """CreateMatchingWorkflow assumes roleArn synchronously; a role created moments ago
    routinely has not finished IAM propagation yet, so retry that specific AccessDenied
    for a bounded window instead of failing fast."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return er.create_matching_workflow(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "AccessDeniedException" and "assuming" in str(e).lower():
                last_err = e
                time.sleep(5)
                continue
            raise
    raise AssertionError(f"create_matching_workflow never succeeded (IAM propagation?): {last_err}")


def _safe_delete_matching_workflow(er, name):
    try:
        er.delete_matching_workflow(workflowName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_glue_table(ctx, columns, suffix="tbl"):
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-er-glue-").lower()
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))

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


def _create_passive_role(ctx):
    import json

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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
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


def _create_schema(ctx, er):
    name = ctx.unique_name("sim2real-er-schema-")
    er.create_schema_mapping(
        schemaName=name,
        mappedInputFields=[
            {"fieldName": "id", "type": "UNIQUE_ID"},
            {"fieldName": "email", "type": "EMAIL_ADDRESS", "matchKey": "email"},
            {"fieldName": "name", "type": "NAME", "matchKey": "name"},
        ],
    )
    ctx.on_cleanup(lambda: _safe_delete_schema(er, name))
    return name


def _safe_delete_schema(er, name):
    try:
        er.delete_schema_mapping(schemaName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_workflow(er, name):
    try:
        er.delete_id_mapping_workflow(workflowName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
