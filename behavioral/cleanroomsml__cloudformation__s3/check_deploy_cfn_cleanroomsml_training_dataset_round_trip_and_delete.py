"""deploy-cfn-cleanroomsml-training-dataset-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-cleanroomsml-training-dataset-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cleanroomsml", "cloudformation", "s3"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def until_raises(fn, timeout_s=90.0):
    """Poll ``fn()`` every 2 s until it raises a ClientError (an eventually consistent delete).

    Grade the error afterwards with expect_error; a success past the deadline fails.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError:
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"still answering after {timeout_s:.0f}s: {result!r}")
        time.sleep(2)


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


# ---- Check-specific: the template, then run(). ----

_DATA_KEY = "data/part-0000.csv"
_DATA_BODY = b"u1,i1,1700000000\n"


def _prereqs_template(db_name: str, table_name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {}},
            "Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "cleanrooms-ml.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                    "Policies": [{
                        "PolicyName": "data-access",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": ["glue:GetTable", "glue:GetDatabase", "glue:GetPartitions"],
                                    "Resource": [
                                        {"Fn::Sub": "arn:${AWS::Partition}:glue:${AWS::Region}:${AWS::AccountId}:catalog"},
                                        {"Fn::Sub": "arn:${AWS::Partition}:glue:${AWS::Region}:${AWS::AccountId}:"
                                                    f"database/{db_name}"},
                                        {"Fn::Sub": "arn:${AWS::Partition}:glue:${AWS::Region}:${AWS::AccountId}:"
                                                    f"table/{db_name}/{table_name}"},
                                    ],
                                },
                                {
                                    "Effect": "Allow",
                                    "Action": ["s3:GetObject", "s3:ListBucket"],
                                    "Resource": [
                                        {"Fn::GetAtt": ["Bucket", "Arn"]},
                                        {"Fn::Sub": "${Bucket.Arn}/*"},
                                    ],
                                },
                            ],
                        },
                    }],
                },
            },
            "GlueDatabase": {
                "Type": "AWS::Glue::Database",
                "Properties": {
                    "CatalogId": {"Ref": "AWS::AccountId"},
                    "DatabaseInput": {"Name": db_name},
                },
            },
            "GlueTable": {
                "Type": "AWS::Glue::Table",
                "DependsOn": ["GlueDatabase", "Bucket"],
                "Properties": {
                    "CatalogId": {"Ref": "AWS::AccountId"},
                    "DatabaseName": {"Ref": "GlueDatabase"},
                    "TableInput": {
                        "Name": table_name,
                        "StorageDescriptor": {
                            "Columns": [
                                {"Name": "user_id", "Type": "string"},
                                {"Name": "item_id", "Type": "string"},
                                {"Name": "timestamp", "Type": "bigint"},
                            ],
                            "Location": {"Fn::Sub": "s3://${Bucket}/data/"},
                            "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                            "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                            "SerdeInfo": {
                                "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                                "Parameters": {"field.delim": ","},
                            },
                        },
                    },
                },
            },
        },
        "Outputs": {
            "BucketName": {"Value": {"Ref": "Bucket"}},
            "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
            "DbName": {"Value": {"Ref": "GlueDatabase"}},
            "TableName": {"Value": {"Ref": "GlueTable"}},
        },
    })


def _add_training_dataset(prereqs_body: str, ds_name: str) -> str:
    template = json.loads(prereqs_body)
    template["Resources"]["TrainingDataset"] = {
        "Type": "AWS::CleanRoomsML::TrainingDataset",
        "DependsOn": ["GlueTable"],
        "Properties": {
            "Name": ds_name,
            "RoleArn": {"Fn::GetAtt": ["Role", "Arn"]},
            "TrainingData": [{
                "Type": "INTERACTIONS",
                "InputConfig": {
                    "Schema": [
                        {"ColumnName": "user_id", "ColumnTypes": ["USER_ID"]},
                        {"ColumnName": "item_id", "ColumnTypes": ["ITEM_ID"]},
                        {"ColumnName": "timestamp", "ColumnTypes": ["TIMESTAMP"]},
                    ],
                    "DataSource": {
                        "GlueDataSource": {
                            "DatabaseName": {"Ref": "GlueDatabase"},
                            "TableName": {"Ref": "GlueTable"},
                        },
                    },
                },
            }],
        },
    }
    template["Outputs"]["DatasetArn"] = {"Value": {"Ref": "TrainingDataset"}}
    template["Outputs"]["DatasetStatus"] = {"Value": {"Fn::GetAtt": ["TrainingDataset", "Status"]}}
    return json.dumps(template)


def _drop(s3, cf, bucket, stack_id):
    """Empty the stack's bucket of the one object this check wrote, then delete the stack."""
    if cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"] == "DELETE_COMPLETE":
        return
    s3.delete_object(Bucket=bucket, Key=_DATA_KEY)
    delete_stack(cf, stack_id)


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation TrainingDataset over a Glue table reads back through CleanRoomsML.

    Ref matches the ListTrainingDatasets entry, the Status GetAtt and the declared role, data
    type, schema and Glue source read back, and deleting the stack removes the dataset.
    """
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    crml = ctx.client("cleanroomsml")
    db_name = ctx.unique_name("sim2real_crmlds_db_")
    table_name = ctx.unique_name("sim2real_crmlds_tbl_")
    ds_name = ctx.unique_name("sim2real-crmlds-")

    prereqs_body = _prereqs_template(db_name, table_name)
    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-crmlds-"), prereqs_body,
                            Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    bucket_name = stack_outputs(cfn, stack_id)["BucketName"]
    # Setup only: the dataset's Glue table needs one data object under its location.
    s3.put_object(Bucket=bucket_name, Key=_DATA_KEY, Body=_DATA_BODY)
    ctx.on_cleanup(lambda: _drop(s3, cfn, bucket_name, stack_id))

    cfn.update_stack(StackName=stack_id, TemplateBody=_add_training_dataset(prereqs_body, ds_name),
                     Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"dataset-adding update ended {status!r}"
    out = stack_outputs(cfn, stack_id)
    ds_arn = out["DatasetArn"]

    listed = [d["trainingDatasetArn"]
              for d in paginate(crml, "list_training_datasets", "trainingDatasets")
              if d["name"] == ds_name]
    assert listed == [ds_arn], f"ListTrainingDatasets named {ds_name!r}: {listed!r}; Ref {ds_arn!r}"
    ds = crml.get_training_dataset(trainingDatasetArn=ds_arn)
    got = (ds["name"], ds["roleArn"], ds["status"], len(ds["trainingData"]),
           ds["trainingData"][0]["type"])
    want = (ds_name, out["RoleArn"], out["DatasetStatus"], 1, "INTERACTIONS")
    assert got == want and ds["status"] == "ACTIVE", f"GetTrainingDataset {got!r}, expected {want!r}"
    config = ds["trainingData"][0]["inputConfig"]
    schema = {c["columnName"]: tuple(c["columnTypes"]) for c in config["schema"]}
    assert schema == {"user_id": ("USER_ID",), "item_id": ("ITEM_ID",), "timestamp": ("TIMESTAMP",)}, (
        f"expected the declared USER_ID/ITEM_ID/TIMESTAMP schema, CleanRoomsML reports {schema!r}"
    )
    source = config["dataSource"]["glueDataSource"]
    assert (source["databaseName"], source["tableName"]) == (db_name, table_name), (
        f"Glue source {source!r}, expected {(db_name, table_name)!r}"
    )

    _drop(s3, cfn, bucket_name, stack_id)
    until_raises(lambda: crml.get_training_dataset(trainingDatasetArn=ds_arn))
    training_dataset_gone = (
        "ResourceNotFoundException",
        f"Training Dataset {ds_arn} does not exist.",
    )
    expect_error(lambda: crml.get_training_dataset(trainingDatasetArn=ds_arn),
                 *training_dataset_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
