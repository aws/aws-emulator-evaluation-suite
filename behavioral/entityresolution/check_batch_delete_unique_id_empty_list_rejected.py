"""batch-delete-unique-id-empty-list-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-delete-unique-id-empty-list-rejected"
GROUP = "overly-permissive"
SERVICES = ["entityresolution"]

_EMAIL = "sim2real-bdu-rec1@example.com"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchDeleteUniqueId rejects an empty uniqueIds list with ValidationException and its exact message,
    leaving the record's match id unchanged; a non-empty list is accepted and GetMatchId then returns a
    different match id for that record."""
    er = ctx.client("entityresolution")
    role_arn = _create_passive_role(ctx)
    schema_name = _create_schema(ctx, er)
    workflow_name = ctx.unique_name("sim2real-er-bdu-wf-")
    bucket = ctx.unique_name("sim2real-er-bdu-out-").lower()
    source_arn = _create_glue_table(ctx, ["id", "email"])
    _create_workflow_with_retry(
        er,
        workflowName=workflow_name,
        inputSourceConfig=[{"inputSourceARN": source_arn, "schemaName": schema_name}],
        outputSourceConfig=[{"outputS3Path": f"s3://{bucket}/out", "output": []}],
        resolutionTechniques={
            "resolutionType": "RULE_MATCHING",
            "ruleBasedProperties": {
                "attributeMatchingModel": "ONE_TO_ONE",
                "rules": [{"ruleName": "emailRule", "matchingKeys": ["email"]}],
                "matchPurpose": "IDENTIFIER_GENERATION",
            },
        },
        roleArn=role_arn,
        tags={"sim2real-check": CHECK},
        incrementalRunConfig={"incrementalRunType": "IMMEDIATE"},
    )
    ctx.on_cleanup(lambda: _safe_delete_workflow(er, workflow_name))

    # Positive control: give the workflow a real record, synchronously, so the delete under test
    # has genuine match data to remove instead of an id nothing ever populated.
    gen = er.generate_match_id(
        workflowName=workflow_name,
        records=[
            {"inputSourceARN": source_arn, "uniqueId": "rec-1", "recordAttributeMap": {"email": _EMAIL}}
        ],
        processingType="CONSISTENT",
    )
    assert not gen.get("failedRecords") and gen.get("matchGroups"), (
        f"GenerateMatchId did not produce a match group for rec-1: {gen!r}"
    )
    before_id = _match_id(er, workflow_name)
    assert before_id, f"GetMatchId found no match right after GenerateMatchId created one: {before_id!r}"

    code, code_message = _error(
        lambda: er.batch_delete_unique_id(workflowName=workflow_name, uniqueIds=[])
    )
    assert code == "ValidationException", (
        f"BatchDeleteUniqueId with an empty uniqueIds list returned {code!r}, expected "
        f'"ValidationException"'
    )
    expected = "1 validation error detected: Value null at 'uniqueIds' failed to satisfy constraint: Member must not be null"
    assert code_message == expected, f"expected message {expected!r}, got {code_message!r}"

    # Effect absent: the rejected call deleted nothing -- GetMatchId, a third operation, still
    # resolves the record to the same match id it had before the rejected call.
    still_id = _match_id(er, workflow_name)
    assert still_id == before_id, (
        f"a rejected empty-list BatchDeleteUniqueId changed the record's match id from "
        f"{before_id!r} to {still_id!r}"
    )

    resp = er.batch_delete_unique_id(workflowName=workflow_name, uniqueIds=["rec-1"])
    assert resp["status"] in ("COMPLETED", "ACCEPTED"), (
        f'BatchDeleteUniqueId with a real uniqueId returned status {resp.get("status")!r}, '
        f'expected "COMPLETED" or "ACCEPTED"'
    )

    # Terminal read: independent of both the generating call and the deleting call, and bounded
    # rather than a bare sleep in case status was ACCEPTED (asynchronous).
    after_id = _poll_until_match_id_changes(er, workflow_name, before_id, timeout_s=90.0)
    assert after_id != before_id, (
        f"after BatchDeleteUniqueId reported deleting rec-1, GetMatchId still resolved the "
        f"record to the same match id {before_id!r}"
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

    db_name = ctx.unique_name("sim2real_er_db_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real-check": CHECK})
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
        tags={"sim2real-check": CHECK},
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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


def _error(fn, description="the call"):
    """Call fn(), which must fail; return its botocore error (code, message). An unexpected
    SUCCESS raises, so a target that accepts what AWS refuses is never read as a mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected {description} to raise a ClientError, but it SUCCEEDED and returned {result!r}")


def _match_id(er, workflow_name):
    """GetMatchId is a read: 'a dry run of an incremental load' that never mutates the
    workflow's match data, unlike GenerateMatchId or BatchDeleteUniqueId. Returns None if the
    record no longer resolves to any match."""
    try:
        return er.get_match_id(workflowName=workflow_name, record={"email": _EMAIL}).get("matchId")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _poll_until_match_id_changes(er, workflow_name, before_id, timeout_s):
    import time as _time

    deadline = _time.monotonic() + timeout_s
    last = before_id
    while _time.monotonic() < deadline:
        last = _match_id(er, workflow_name)
        if last != before_id:
            return last
        _time.sleep(3)
    raise AssertionError(
        f"GetMatchId still resolved rec-1 to {before_id!r} {timeout_s}s after BatchDeleteUniqueId"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
