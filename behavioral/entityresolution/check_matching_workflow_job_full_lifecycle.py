"""matching-workflow-job-full-lifecycle."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "matching-workflow-job-full-lifecycle"
GROUP = "data-plane"
SERVICES = ["entityresolution"]

_MATCH_ID_RE = re.compile(r"[0-9a-f]{32}")


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A matching job reaches SUCCEEDED with 4 input and 4 processed records, DeleteMatchingWorkflow fails with
    ConflictException while it runs, and its S3 output groups the two shared-email records under one
    matchId and the other two under another; after deletion, reads and StartMatchingJob are not found."""
    er = ctx.client("entityresolution")
    input_bucket = _create_bucket(ctx, "in")
    output_bucket = _create_bucket(ctx, "out")
    _upload_input_csv(ctx, input_bucket)
    db_name, table_name = _create_glue_table(ctx, input_bucket)
    role_arn = _create_er_role(ctx, input_bucket, output_bucket)

    schema_name = ctx.unique_name("sim2real-er-job-schema-")
    er.create_schema_mapping(
        schemaName=schema_name,
        mappedInputFields=[
            {"fieldName": "id", "type": "UNIQUE_ID"},
            {"fieldName": "name", "type": "NAME", "matchKey": "name"},
            {"fieldName": "email", "type": "EMAIL_ADDRESS", "matchKey": "email"},
        ],
        tags={"sim2real": "entityresolution"},
    )
    ctx.on_cleanup(lambda: _safe_delete_schema(er, schema_name))

    account = ctx.client("sts").get_caller_identity()["Account"]
    table_arn = f"arn:aws:glue:{ctx.region}:{account}:table/{db_name}/{table_name}"
    workflow_name = ctx.unique_name("sim2real-er-job-wf-")
    output_prefix = f"s3://{output_bucket}/output"
    _create_workflow_with_retry(
        er,
        workflowName=workflow_name,
        inputSourceConfig=[{"inputSourceARN": table_arn, "schemaName": schema_name}],
        outputSourceConfig=[
            {
                "outputS3Path": output_prefix,
                "output": [{"name": "id"}, {"name": "name"}, {"name": "email"}],
            }
        ],
        resolutionTechniques={
            "resolutionType": "RULE_MATCHING",
            "ruleBasedProperties": {
                "attributeMatchingModel": "ONE_TO_ONE",
                "matchPurpose": "IDENTIFIER_GENERATION",
                "rules": [{"ruleName": "emailRule", "matchingKeys": ["email"]}],
            },
        },
        roleArn=role_arn,
        tags={"sim2real": "entityresolution"},
    )
    ctx.on_cleanup(lambda: _safe_delete_workflow(er, workflow_name))

    job_id = _start_job_with_retry(er, workflow_name)

    # The job cannot possibly be terminal yet (it just started) -- deletion must be rejected.
    conflict_code, conflict_message = _error(lambda: er.delete_matching_workflow(workflowName=workflow_name))
    assert conflict_code == "ConflictException", f"expected ConflictException while job is non-terminal, got {conflict_code}"
    expected = f"Job associated with workflow {workflow_name} is currently running, failed to delete"
    assert conflict_message == expected, f"expected message {expected!r}, got {conflict_message!r}"
    still_there = er.get_matching_workflow(workflowName=workflow_name)["workflowName"]
    assert still_there == workflow_name, f"rejected delete must leave the workflow in place, got {still_there!r}"

    final = _poll_job_to_terminal(er, workflow_name, job_id, timeout_s=900.0)
    assert final["status"] == "SUCCEEDED", final.get("errorDetails")
    assert final["metrics"]["inputRecords"] == 4, f"expected 4 input records, got {final['metrics']}"
    assert final["metrics"]["totalRecordsProcessed"] == 4, f"expected 4 processed records, got {final['metrics']}"

    dup_match_ids, other_match_ids = _read_match_ids_from_output(ctx, output_bucket)
    assert len(dup_match_ids) == 2 and len(set(dup_match_ids)) == 1, dup_match_ids
    assert len(other_match_ids) == 2 and len(set(other_match_ids)) == 1, other_match_ids
    assert dup_match_ids[0] != other_match_ids[0], (
        f"the two distinct email groups must resolve to different matchIds, got {dup_match_ids[0]} for both"
    )

    # Positive control: now that the job is terminal, delete succeeds.
    er.delete_matching_workflow(workflowName=workflow_name)
    get_code, get_message = _error(lambda: er.get_matching_workflow(workflowName=workflow_name))
    assert get_code == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {get_code}"
    expected = "MatchingWorkflow Not Found"
    assert get_message == expected, f"expected message {expected!r}, got {get_message!r}"
    start_code, start_message = _error(lambda: er.start_matching_job(workflowName=workflow_name))
    assert start_code == "ResourceNotFoundException", (
        f"a mutation on the deleted workflow must also fail not-found, got {start_code}"
    )
    expected = "Workflow not found."
    assert start_message == expected, f"expected message {expected!r}, got {start_message!r}"


def _create_bucket(ctx, tag):
    s3 = ctx.client("s3")
    name = ctx.unique_name(f"sim2real-er-job-{tag}-").lower()
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "entityresolution"}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name):
    s3 = ctx.client("s3")
    try:
        token = None
        while True:
            kwargs = {"Bucket": name}
            if token:
                kwargs["ContinuationToken"] = token
            resp = s3.list_objects_v2(**kwargs)
            for obj in resp.get("Contents", []):
                s3.delete_object(Bucket=name, Key=obj["Key"])
            token = resp.get("NextContinuationToken")
            if not token:
                break
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _upload_input_csv(ctx, bucket):
    s3 = ctx.client("s3")
    csv_body = (
        "id,name,email\n"
        "1,Jane Doe,dup@example.com\n"
        "2,Jane D,dup@example.com\n"
        "3,John Smith,other@example.com\n"
        "4,J Smith,other@example.com\n"
    )
    s3.put_object(Bucket=bucket, Key="input/records.csv", Body=csv_body.encode("utf-8"))


def _create_glue_table(ctx, input_bucket):
    glue = ctx.client("glue")
    db_name = ctx.unique_name("sim2real_er_db_").replace("-", "_")
    table_name = "records"
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": "entityresolution"})
    ctx.on_cleanup(lambda: _safe_delete_database(glue, db_name))
    glue.create_table(
        DatabaseName=db_name,
        TableInput={
            "Name": table_name,
            "StorageDescriptor": {
                "Columns": [
                    {"Name": "id", "Type": "string"},
                    {"Name": "name", "Type": "string"},
                    {"Name": "email", "Type": "string"},
                ],
                "Location": f"s3://{input_bucket}/input/",
                "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                "SerdeInfo": {
                    "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                    "Parameters": {"field.delim": ","},
                },
            },
            "TableType": "EXTERNAL_TABLE",
            "Parameters": {"skip.header.line.count": "1", "classification": "csv"},
        },
    )
    ctx.on_cleanup(lambda: _safe_delete_table(glue, db_name, table_name))
    return db_name, table_name


def _safe_delete_table(glue, db_name, table_name):
    try:
        glue.delete_table(DatabaseName=db_name, Name=table_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _safe_delete_database(glue, db_name):
    try:
        glue.delete_database(Name=db_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _create_er_role(ctx, input_bucket, output_bucket):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-er-job-role-")
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
        Tags=[{"Key": "sim2real", "Value": "entityresolution"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_delete_role(iam, role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{input_bucket}", f"arn:aws:s3:::{input_bucket}/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{output_bucket}", f"arn:aws:s3:::{output_bucket}/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["glue:GetTable", "glue:GetDatabase", "glue:GetPartitions", "glue:GetTables"],
                "Resource": "*",
            },
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="er-job-access", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: _safe_delete_role_policy(iam, role_name))
    return role_arn


def _safe_delete_role_policy(iam, role_name):
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName="er-job-access")
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


def _create_workflow_with_retry(er, timeout_s=120.0, **kwargs):
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


def _start_job_with_retry(er, workflow_name, timeout_s=120.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return er.start_matching_job(workflowName=workflow_name)["jobId"]
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException"):
                last_err = e
                time.sleep(5)
                continue
            raise
    raise AssertionError(f"StartMatchingJob never accepted (IAM/Glue propagation?): {last_err}")


def _poll_job_to_terminal(er, workflow_name, job_id, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = er.get_matching_job(workflowName=workflow_name, jobId=job_id)
        if last["status"] in ("SUCCEEDED", "FAILED"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"matching job never reached a terminal state within {timeout_s}s: {last}")


def _read_match_ids_from_output(ctx, output_bucket):
    s3 = ctx.client("s3")
    text_chunks = []
    token = None
    while True:
        kwargs = {"Bucket": output_bucket, "Prefix": "output/"}
        if token:
            kwargs["ContinuationToken"] = token
        resp = s3.list_objects_v2(**kwargs)
        for obj in resp.get("Contents", []):
            body = s3.get_object(Bucket=output_bucket, Key=obj["Key"])["Body"].read()
            text_chunks.append(body.decode("utf-8", errors="replace"))
        token = resp.get("NextContinuationToken")
        if not token:
            break
    full_text = "\n".join(text_chunks)
    if not full_text.strip():
        raise AssertionError("no output objects were written under the output S3 prefix")

    dup_match_ids = []
    other_match_ids = []
    for line in full_text.splitlines():
        found = _MATCH_ID_RE.findall(line)
        if "dup@example.com" in line and found:
            dup_match_ids.append(found[-1])
        elif "other@example.com" in line and found:
            other_match_ids.append(found[-1])
    return dup_match_ids, other_match_ids


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
