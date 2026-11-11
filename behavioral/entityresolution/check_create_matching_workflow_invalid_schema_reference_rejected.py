"""create-matching-workflow-invalid-schema-reference-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-matching-workflow-invalid-schema-reference-rejected"
GROUP = "overly-permissive"
SERVICES = ["entityresolution"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateMatchingWorkflow raises ValidationException when inputSourceConfig references a
    schemaName that does not exist, and no workflow is created; pointing the same request at a
    real schema mapping in the same file succeeds."""
    er = ctx.client("entityresolution")
    role_arn = _create_passive_role(ctx)
    source_arn = f"arn:aws:glue:{ctx.region}:{ctx.client('sts').get_caller_identity()['Account']}:table/sim2real_nonexistent_db/sim2real_nonexistent_tbl"
    bucket = ctx.unique_name("sim2real-er-out-").lower()
    missing_schema = ctx.unique_name("sim2real-er-noschema-")
    workflow_name = ctx.unique_name("sim2real-er-badref-wf-")

    def _create():
        er.create_matching_workflow(
            workflowName=workflow_name,
            inputSourceConfig=[{"inputSourceARN": source_arn, "schemaName": missing_schema}],
            outputSourceConfig=[{"outputS3Path": f"s3://{bucket}/out", "output": []}],
            resolutionTechniques={
                "resolutionType": "RULE_MATCHING",
                "ruleBasedProperties": {
                    "attributeMatchingModel": "ONE_TO_ONE",
                    "rules": [{"ruleName": "emailRule", "matchingKeys": ["email"]}],
                },
            },
            roleArn=role_arn,
        )

    code, code_message = _error(_create, "create_matching_workflow with a missing schemaName")
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = f"References schema mapping(s) which does not exist: [{missing_schema}]"
    assert code_message == expected, f"expected message {expected!r}, got {code_message!r}"
    get_code, get_code_message = _error(
        lambda: er.get_matching_workflow(workflowName=workflow_name),
        "get_matching_workflow for a workflow that was never created",
    )
    assert get_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException (workflow must not exist), got {get_code!r}"
    )
    expected = "MatchingWorkflow Not Found"
    assert get_code_message == expected, f"expected message {expected!r}, got {get_code_message!r}"

    real_schema = _create_schema(ctx, er)
    good_source_arn = _create_glue_table(ctx, ["id", "email"])
    good_workflow_name = ctx.unique_name("sim2real-er-goodref-wf-")
    _create_workflow_with_retry(
        er,
        workflowName=good_workflow_name,
        inputSourceConfig=[{"inputSourceARN": good_source_arn, "schemaName": real_schema}],
        outputSourceConfig=[{"outputS3Path": f"s3://{bucket}/out", "output": []}],
        resolutionTechniques={
            "resolutionType": "RULE_MATCHING",
            "ruleBasedProperties": {
                "attributeMatchingModel": "ONE_TO_ONE",
                "rules": [{"ruleName": "emailRule", "matchingKeys": ["email"]}],
            },
        },
        roleArn=role_arn,
    )
    ctx.on_cleanup(lambda: _safe_delete_workflow(er, good_workflow_name))
    got_name = er.get_matching_workflow(workflowName=good_workflow_name)["workflowName"]
    assert got_name == good_workflow_name, (
        f"expected the same-shaped request with a real schema reference to succeed and be "
        f"readable back as {good_workflow_name!r}, got {got_name!r}"
    )


def _create_workflow_with_retry(er, timeout_s=240.0, **kwargs):
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
        # CreateBucket rejects an explicit LocationConstraint for us-east-1 itself; this is an
        # S3 API constant, not a pin of the check to that region.
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


def _create_schema(ctx, er):
    name = ctx.unique_name("sim2real-er-schema-")
    er.create_schema_mapping(
        schemaName=name,
        mappedInputFields=[
            {"fieldName": "id", "type": "UNIQUE_ID"},
            {"fieldName": "email", "type": "EMAIL_ADDRESS", "matchKey": "email"},
        ],
    )
    ctx.on_cleanup(lambda: _safe_delete_schema(er, name))
    return name


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


def _error(fn, description="the call"):
    """Call fn(), which must fail; return its botocore error (code, message). An unexpected
    SUCCESS raises, so a target that accepts what AWS refuses is never read as a mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected {description} to raise a ClientError, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
