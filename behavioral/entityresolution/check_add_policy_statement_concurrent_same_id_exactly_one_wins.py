"""add-policy-statement-concurrent-same-id-exactly-one-wins."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "add-policy-statement-concurrent-same-id-exactly-one-wins"
GROUP = "concurrency"
SERVICES = ["entityresolution"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent AddPolicyStatement calls with one statementId: exactly one succeeds, every other gets
    ValidationException "Statement ID already exists in document", and the policy holds exactly one
    statement with that Sid (no lost or duplicated update)."""
    er = ctx.client("entityresolution")
    ns_name = ctx.unique_name("sim2real-er-race-")
    schema_name = _create_schema(ctx, er)
    role_arn = _create_passive_role(ctx)
    source_arn = _create_glue_table(ctx, ["id", "email"])
    created = _create_namespace_with_retry(er,
        idNamespaceName=ns_name,
        type="SOURCE",
        roleArn=role_arn,
        inputSourceConfig=[{"inputSourceARN": source_arn, "schemaName": schema_name}],
        idMappingWorkflowProperties=[
            {
                "idMappingType": "RULE_BASED",
                "ruleBasedProperties": {
                    "attributeMatchingModel": "ONE_TO_ONE",
                    "recordMatchingModels": ["ONE_SOURCE_TO_ONE_TARGET"],
                    "ruleDefinitionTypes": ["SOURCE"],
                    "rules": [{"ruleName": "emailRule", "matchingKeys": ["email"]}],
                },
            }
        ],
        tags={"sim2real": CHECK},
    )
    arn = created["idNamespaceArn"]
    ctx.on_cleanup(lambda: _safe_delete_namespace(er, ns_name))
    ctx.on_cleanup(lambda: _safe_delete_policy_statement(er, arn, "raceStmt"))

    n_racers = 6
    principal_account = ctx.client("sts").get_caller_identity()["Account"]

    def _racer(i):
        try:
            er.add_policy_statement(
                arn=arn,
                statementId="raceStmt",
                effect="Allow",
                action=["entityresolution:GetIdNamespace"],
                principal=[principal_account],
            )
            return ("ok", None)
        except ClientError as e:
            return ("error", e.response["Error"])

    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        results = list(pool.map(_racer, range(n_racers)))

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]
    assert len(successes) == 1, f"expected exactly one winner, got {len(successes)}: {results}"
    assert len(failures) == n_racers - 1, (
        f"expected {n_racers - 1} losers, got {len(failures)}: {results}"
    )
    assert all(err["Code"] == "ValidationException" for _, err in failures), failures
    assert all(
        err["Message"] == "Statement ID already exists in document" for _, err in failures
    ), failures

    policy = json.loads(er.get_policy(arn=arn)["policy"])
    matching = [s for s in policy["Statement"] if s["Sid"] == "raceStmt"]
    assert len(matching) == 1, f"expected exactly one raceStmt statement, found {len(matching)}: {policy}"


def _create_namespace_with_retry(er, timeout_s=120.0, **kwargs):
    """CreateIdNamespace synchronously validates that the referenced Glue Catalog table exists
    and is readable. A table that was just created can lag behind eventual consistency, so
    retry on that specific error for a bounded window instead of failing fast."""
    import time as _time

    deadline = _time.monotonic() + timeout_s
    last_err = None
    while _time.monotonic() < deadline:
        try:
            return er.create_id_namespace(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "")
            retryable = code == "AccessDeniedException" or (
                code == "ValidationException" and "inputsourcearn" in msg.lower()
            )
            if retryable:
                last_err = e
                _time.sleep(3)
                continue
            raise
    raise AssertionError(f"create_id_namespace never succeeded (Glue propagation?): {last_err}")

def _create_glue_table(ctx, columns, suffix="tbl"):
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-er-glue-").lower()
    kwargs = {}
    # us-east-1 is the one region where S3 CreateBucket rejects an explicit LocationConstraint.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))

    db_name = ctx.unique_name("sim2real_er_db_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": db_name}, Tags={"sim2real": "true"})
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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


def _create_schema(ctx, er):
    name = ctx.unique_name("sim2real-er-schema-")
    er.create_schema_mapping(
        schemaName=name,
        mappedInputFields=[
            {"fieldName": "id", "type": "UNIQUE_ID"},
            {"fieldName": "email", "type": "EMAIL_ADDRESS", "matchKey": "email"},
        ],
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _safe_delete_schema(er, name))
    return name


def _safe_delete_schema(er, name):
    try:
        er.delete_schema_mapping(schemaName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_namespace(er, name):
    try:
        er.delete_id_namespace(idNamespaceName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_policy_statement(er, arn, statement_id):
    try:
        er.delete_policy_statement(arn=arn, statementId=statement_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
