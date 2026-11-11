"""id-mapping-workflow-create-get-delete-roundtrip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "id-mapping-workflow-create-get-delete-roundtrip"
GROUP = "control-plane"
SERVICES = ["entityresolution"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateIdMappingWorkflow persists idMappingTechniques/inputSourceConfig; DeleteIdMappingWorkflow
    removes it and it disappears from both GetIdMappingWorkflow and ListIdMappingWorkflows."""
    er = ctx.client("entityresolution")
    schema_name = _create_schema(ctx, er)
    workflow_name = ctx.unique_name("sim2real-er-idmw-")
    # A TARGET-type ID namespace's own inputSourceConfig (on CreateIdNamespace itself) rejects a
    # Glue table ARN with ValidationException demanding a matchingworkflow ARN instead, and
    # rejects an absent inputSourceConfig too ("type is set as type:TARGET. Provide
    # inputSourceConfig") -- real AWS applies a per-type business rule beyond the shape's shared
    # regex and the field's own optional trait: a TARGET namespace's data source must be an
    # existing MatchingWorkflow's resolved output, never a raw Glue table. SOURCE keeps its Glue
    # table, which is the documented input for that type.
    matching_workflow_arn = _create_matching_workflow(ctx, er, schema_name)
    source_ns_arn = _create_namespace(ctx, er, "SOURCE", schema_name)
    target_ns_arn = _create_namespace(ctx, er, "TARGET", schema_name, matching_workflow_arn)

    er.create_id_mapping_workflow(
        workflowName=workflow_name,
        # schemaName is only for a raw Glue table inputSourceARN; an idnamespace ARN already
        # carries its own schema binding and CreateIdMappingWorkflow rejects schemaName alongside
        # one ("Schema name is not allowed").
        inputSourceConfig=[
            {"inputSourceARN": source_ns_arn, "type": "SOURCE"},
            {"inputSourceARN": target_ns_arn, "type": "TARGET"},
        ],
        idMappingTechniques={
            "idMappingType": "RULE_BASED",
            "ruleBasedProperties": {
                "attributeMatchingModel": "ONE_TO_ONE",
                "recordMatchingModel": "ONE_SOURCE_TO_ONE_TARGET",
                "ruleDefinitionType": "TARGET",
                "rules": [{"ruleName": "emailRule", "matchingKeys": ["email"]}],
            },
        },
        tags={"sim2real": "id-mapping-workflow-create-get-delete-roundtrip"},
    )
    ctx.on_cleanup(lambda: _safe_delete_workflow(er, workflow_name))

    got = er.get_id_mapping_workflow(workflowName=workflow_name)
    assert got["workflowName"] == workflow_name
    assert got["idMappingTechniques"]["idMappingType"] == "RULE_BASED"

    names_before = {w["workflowName"] for w in _list_all(er, workflow_name)}
    assert workflow_name in names_before

    er.delete_id_mapping_workflow(workflowName=workflow_name)
    code, code_message = _error(lambda: er.get_id_mapping_workflow(workflowName=workflow_name))
    assert code == "ResourceNotFoundException"
    expected = "IdMappingWorkflow Not Found"
    assert code_message == expected, f"expected message {expected!r}, got {code_message!r}"

    names_after = {w["workflowName"] for w in _list_all(er, workflow_name)}
    assert workflow_name not in names_after


def _list_all(er, needle):
    out = []
    token = None
    while True:
        kwargs = {"nextToken": token} if token else {}
        resp = er.list_id_mapping_workflows(**kwargs)
        out.extend(resp["workflowSummaries"])
        token = resp.get("nextToken")
        if not token or any(w["workflowName"] == needle for w in out):
            break
    return out


def _create_matching_workflow(ctx, er, schema_name):
    """A completed MatchingWorkflow's ARN is the only inputSourceARN a TARGET-type ID namespace
    accepts. No run is needed -- CreateMatchingWorkflow returns the ARN synchronously."""
    name = ctx.unique_name("sim2real-er-mw-")
    role_arn = _create_passive_role(ctx)
    source_arn = _create_glue_table(ctx, ["id", "email"], suffix="mw-src")
    bucket = ctx.unique_name("sim2real-er-mw-out-").lower()
    s3 = ctx.client("s3")
    kwargs = {}
    if ctx.region != "us-east-1":
        # us-east-1 is CreateBucket's own default region and rejects an explicit
        # LocationConstraint for it -- this is an S3 API quirk, not a region pin.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))

    created = _retry_on_propagation(
        lambda: er.create_matching_workflow(
            workflowName=name,
            inputSourceConfig=[{"inputSourceARN": source_arn, "schemaName": schema_name}],
            outputSourceConfig=[
                {
                    "outputS3Path": f"s3://{bucket}/output/",
                    "output": [{"name": "id"}, {"name": "email"}],
                }
            ],
            resolutionTechniques={
                "resolutionType": "RULE_MATCHING",
                "ruleBasedProperties": {
                    "attributeMatchingModel": "ONE_TO_ONE",
                    "rules": [{"ruleName": "emailRule", "matchingKeys": ["email"]}],
                },
            },
            roleArn=role_arn,
            tags={"sim2real": "id-mapping-workflow-create-get-delete-roundtrip"},
        )
    )
    ctx.on_cleanup(lambda: _safe_delete_matching_workflow(er, name))
    return created["workflowArn"]


def _safe_delete_matching_workflow(er, name):
    try:
        er.delete_matching_workflow(workflowName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_namespace(ctx, er, ns_type, schema_name, matching_workflow_arn=None):
    name = ctx.unique_name(f"sim2real-er-idns-{ns_type.lower()}-")
    role_arn = _create_passive_role(ctx)
    source_arn = (
        _create_glue_table(ctx, ["id", "email"], suffix=ns_type.lower())
        if ns_type == "SOURCE"
        else matching_workflow_arn
    )
    source_kwargs = {
        "roleArn": role_arn,
        "inputSourceConfig": [{"inputSourceARN": source_arn, "schemaName": schema_name}],
    }
    created = _retry_on_propagation(
        lambda: er.create_id_namespace(
            idNamespaceName=name,
            type=ns_type,
            **source_kwargs,
            idMappingWorkflowProperties=[
                {
                    "idMappingType": "RULE_BASED",
                    "ruleBasedProperties": {
                        "attributeMatchingModel": "ONE_TO_ONE",
                        "recordMatchingModels": ["ONE_SOURCE_TO_ONE_TARGET"],
                        # Both namespaces must declare the SAME ruleDefinitionTypes -- "the
                        # limitations specified for the source and target must be compatible"
                        # (docs). Restricting each namespace to only its own type made every
                        # ruleDefinitionType real AWS could pick for the id-mapping-workflow
                        # itself invalid ("Invalid ruleDefinitionType SOURCE/TARGET in IdMapping
                        # RuleBasedConfig"), since neither side allowed the other's value.
                        "ruleDefinitionTypes": ["SOURCE", "TARGET"],
                        "rules": [{"ruleName": "emailRule", "matchingKeys": ["email"]}],
                    },
                }
            ],
            tags={"sim2real": "id-mapping-workflow-create-get-delete-roundtrip"},
        )
    )
    ctx.on_cleanup(lambda: _safe_delete_namespace(er, name))
    return created["idNamespaceArn"]


def _retry_on_propagation(fn, timeout_s=240.0):
    """CreateIdNamespace/CreateMatchingWorkflow synchronously validate that the assumed role and
    the referenced Glue Catalog table are both usable. A role or table created moments earlier in
    this same check can lag behind IAM/Glue eventual consistency, so retry on those two specific
    errors for a bounded window instead of failing fast."""
    import time as _time

    deadline = _time.monotonic() + timeout_s
    last_err = None
    while _time.monotonic() < deadline:
        try:
            return fn()
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
    raise AssertionError(f"never succeeded (IAM/Glue propagation?): {last_err}")


def _safe_delete_namespace(er, name):
    try:
        er.delete_id_namespace(idNamespaceName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_glue_table(ctx, columns, suffix="tbl"):
    glue = ctx.client("glue")
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-er-glue-").lower()
    kwargs = {}
    if ctx.region != "us-east-1":
        # us-east-1 is CreateBucket's own default region and rejects an explicit
        # LocationConstraint for it -- this is an S3 API quirk, not a region pin.
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "entityresolution-id-mapping-workflow-roundtrip"}],
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
        tags={"sim2real": "id-mapping-workflow-create-get-delete-roundtrip"},
    )
    ctx.on_cleanup(lambda: _safe_delete_schema(er, name))
    return name


def _error(fn, description="the call"):
    """Call fn(), which must fail; return its botocore error (code, message). An unexpected
    SUCCESS raises, so a target that accepts what AWS refuses is never read as a mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected {description} to raise a ClientError, but it SUCCEEDED and returned {result!r}")


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
