"""deploy-cfn-cleanroomsml-training-dataset-empty-s3-location-rejected."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-cfn-cleanroomsml-training-dataset-empty-s3-location-rejected"
GROUP = "deploy"
SERVICES = ["cleanroomsml", "cloudformation", "s3"]

_DATA_KEY = "data/part-0000.csv"
_DATA_BODY = b"u1,i1,1700000000\n"

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


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


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


def handler_reason(reason, account, *names):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names), m["code"]


# ---- Check-specific: the template, then run(). ----

def _prereqs_template(db_name: str, table_name: str) -> dict:
    return {
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
    }


def _with_training_dataset(template: dict, ds_name: str) -> str:
    template = json.loads(json.dumps(template))
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
    return json.dumps(template)


def _drop(s3, cf, bucket, stack_id):
    """Empty the stack's bucket of the one object this check wrote, then delete the stack."""
    if cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"] == "DELETE_COMPLETE":
        return
    s3.delete_object(Bucket=bucket, Key=_DATA_KEY)
    delete_stack(cf, stack_id)


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation TrainingDataset over a Glue table with no data object is refused and rolled back.

    CleanRoomsML's exact refusal is graded and no dataset of that name exists; the identical
    resource added once the location holds an object deploys and reads back.
    """
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    crml = ctx.client("cleanroomsml")
    db_name = ctx.unique_name("sim2real_crmldsr_db_")
    table_name = ctx.unique_name("sim2real_crmldsr_tbl_")
    ds_name = ctx.unique_name("sim2real-crmldsr-")

    prereqs = _prereqs_template(db_name, table_name)
    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-crmldsr-"), json.dumps(prereqs),
                            Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    prereq_out = stack_outputs(cfn, stack_id)
    bucket_name = prereq_out["BucketName"]

    dataset_template = _with_training_dataset(prereqs, ds_name)
    cfn.update_stack(StackName=stack_id, TemplateBody=dataset_template, Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_ROLLBACK_COMPLETE", f"update with no data object ended {status!r}"
    got = handler_reason(failed_reason(stack_events(cfn, stack_id), "TrainingDataset"),
                         ctx.account, bucket_name)
    want = ("Failed to find any non-zero sized objects in this S3 location s3://<name>/data/. "
            "(Service: CleanRoomsMl, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
            "InvalidRequest")
    assert got == want, f"handler reason {got!r}, expected {want!r}"
    names = [d["name"] for d in paginate(crml, "list_training_datasets", "trainingDatasets")]
    assert ds_name not in names, f"the rolled-back training dataset {ds_name!r} is listed"

    # Positive control: the same resource once the location holds an object (setup through S3).
    s3.put_object(Bucket=bucket_name, Key=_DATA_KEY, Body=_DATA_BODY)
    ctx.on_cleanup(lambda: _drop(s3, cfn, bucket_name, stack_id))
    cfn.update_stack(StackName=stack_id, TemplateBody=dataset_template, Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"update with a data object ended {status!r}"
    ds_arn = stack_outputs(cfn, stack_id)["DatasetArn"]
    listed = [d["trainingDatasetArn"]
              for d in paginate(crml, "list_training_datasets", "trainingDatasets")
              if d["name"] == ds_name]
    assert listed == [ds_arn], f"ListTrainingDatasets named {ds_name!r}: {listed!r}; Ref {ds_arn!r}"
    ds = crml.get_training_dataset(trainingDatasetArn=ds_arn)
    config = ds["trainingData"][0]["inputConfig"]
    got = (ds["name"], ds["roleArn"], [t["type"] for t in ds["trainingData"]],
           {c["columnName"]: c["columnTypes"] for c in config["schema"]},
           config["dataSource"]["glueDataSource"]["databaseName"],
           config["dataSource"]["glueDataSource"]["tableName"])
    want = (ds_name, prereq_out["RoleArn"], ["INTERACTIONS"],
            {"user_id": ["USER_ID"], "item_id": ["ITEM_ID"], "timestamp": ["TIMESTAMP"]},
            db_name, table_name)
    assert got == want, f"control dataset {got!r}, expected {want!r}"
    _drop(s3, cfn, bucket_name, stack_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
