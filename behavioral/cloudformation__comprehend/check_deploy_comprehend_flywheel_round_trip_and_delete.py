"""deploy-comprehend-flywheel-round-trip-and-delete."""
from __future__ import annotations

import json
import time
from urllib.parse import urlparse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-comprehend-flywheel-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "comprehend"]

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

_FLYWHEEL_NOT_FOUND = (
    "ResourceNotFoundException", "RESOURCE_NOT_FOUND: Could not find specified resource."
)
_TEMPLATE_TAGS = [{"Key": "sim2real-check", "Value": CHECK}]


def _template(flywheel_name: str) -> str:
    t = _TEMPLATE_TAGS
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "comprehend.amazonaws.com"},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"aws:SourceAccount": {"Ref": "AWS::AccountId"}}},
        }],
    }
    access_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"],
             "Resource": {"Fn::Sub": "arn:${AWS::Partition}:s3:::${DataLakeBucket}/*"}},
            {"Effect": "Allow", "Action": "s3:ListBucket",
             "Resource": {"Fn::Sub": "arn:${AWS::Partition}:s3:::${DataLakeBucket}"}},
        ],
    }
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "DataLakeBucket": {"Type": "AWS::S3::Bucket", "Properties": {"Tags": t}},
            "DataAccessRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": trust,
                    "Policies": [{"PolicyName": "data-lake-access", "PolicyDocument": access_policy}],
                    "Tags": t,
                },
            },
            "Flywheel": {
                "Type": "AWS::Comprehend::Flywheel",
                "Properties": {
                    "FlywheelName": flywheel_name,
                    "DataAccessRoleArn": {"Fn::GetAtt": ["DataAccessRole", "Arn"]},
                    "DataLakeS3Uri": {"Fn::Sub": "s3://${DataLakeBucket}/datalake"},
                    "ModelType": "DOCUMENT_CLASSIFIER",
                    "TaskConfig": {
                        "LanguageCode": "en",
                        "DocumentClassificationConfig": {
                            "Mode": "MULTI_CLASS",
                            "Labels": ["POSITIVE", "NEGATIVE"],
                        },
                    },
                    "Tags": t,
                },
            },
        },
        "Outputs": {
            "FlywheelArn": {"Value": {"Ref": "Flywheel"}},
            "FlywheelArnAttr": {"Value": {"Fn::GetAtt": ["Flywheel", "Arn"]}},
            "RoleArn": {"Value": {"Fn::GetAtt": ["DataAccessRole", "Arn"]}},
            "BucketName": {"Value": {"Ref": "DataLakeBucket"}},
        },
    })


def _list_flywheels(comprehend) -> list[dict]:
    """Every ListFlywheels summary across all pages (botocore ships no paginator for it)."""
    summaries, kwargs = [], {}
    while True:
        page = comprehend.list_flywheels(**kwargs)
        summaries.extend(page.get("FlywheelSummaryList", []))
        if not page.get("NextToken"):
            return summaries
        kwargs["NextToken"] = page["NextToken"]


def _empty_data_lake(cf, s3, stack_id: str) -> None:
    """Delete every object the flywheel wrote into the stack's bucket, so the stack can delete.

    A stack already DELETE_COMPLETE has no bucket left to empty.
    """
    if cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"] == "DELETE_COMPLETE":
        return
    buckets = [r["PhysicalResourceId"] for r in paginate(
        cf, "list_stack_resources", "StackResourceSummaries", StackName=stack_id)
        if r["LogicalResourceId"] == "DataLakeBucket" and r.get("PhysicalResourceId")
        and r["ResourceStatus"] != "DELETE_COMPLETE"]
    for bucket in buckets:
        objects = [{"Key": o["Key"]}
                   for o in paginate(s3, "list_objects_v2", "Contents", Bucket=bucket)]
        for i in range(0, len(objects), 1000):
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objects[i:i + 1000]})


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::Comprehend::Flywheel reaches Status 'ACTIVE' in Comprehend's own
    DescribeFlywheel with the declared DataAccessRoleArn, DataLakeS3Uri, ModelType and
    TaskConfig and Tags; deleting the stack drives DescribeFlywheel to ResourceNotFoundException.
    """
    cfn = ctx.client("cloudformation")
    comprehend = ctx.client("comprehend")
    s3 = ctx.client("s3")
    stack_name = ctx.unique_name("sim2real-behav-cfnflywheel-")
    flywheel_name = ctx.unique_name("sim2real-behav-fw-")

    stack_id = create_stack(ctx, cfn, stack_name, _template(flywheel_name),
                            Capabilities=["CAPABILITY_IAM"])
    # LIFO: the bucket is emptied before the registered stack delete runs.
    ctx.on_cleanup(lambda: _empty_data_lake(cfn, s3, stack_id))

    created = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert created == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {created!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )

    outputs = stack_outputs(cfn, stack_id)
    flywheel_arn = outputs["FlywheelArn"]
    partition = stack_id.split(":")[1]
    want_arn = f"arn:{partition}:comprehend:{ctx.region}:{ctx.account}:flywheel/{flywheel_name}"
    assert (flywheel_arn, outputs["FlywheelArnAttr"]) == (want_arn, want_arn), (
        f"expected Ref and GetAtt Arn to be the documented flywheel ARN {want_arn!r}, got "
        f"Ref {flywheel_arn!r}, GetAtt {outputs['FlywheelArnAttr']!r}"
    )
    # Independent read: ListFlywheels entries matched against the ARN built from the name.
    listed = [f["FlywheelArn"] for f in _list_flywheels(comprehend)
              if f["FlywheelArn"] == want_arn]
    assert listed == [want_arn], (
        f"expected ListFlywheels to list the stack's flywheel once, got {len(listed)} entries"
    )
    props = comprehend.describe_flywheel(FlywheelArn=want_arn)["FlywheelProperties"]
    assert props["FlywheelArn"] == want_arn, (
        f"expected DescribeFlywheel's FlywheelArn {want_arn!r}, got {props['FlywheelArn']!r}"
    )
    assert props["Status"] == "ACTIVE", (
        f"expected Status 'ACTIVE' once CREATE_COMPLETE, Comprehend reports {props['Status']!r}"
    )
    assert props["DataAccessRoleArn"] == outputs["RoleArn"], (
        f"expected DataAccessRoleArn {outputs['RoleArn']!r}, got {props['DataAccessRoleArn']!r}"
    )
    # Comprehend nests the active data lake version under the declared location
    # (<declared>/<flywheel-name>/schemaVersion=<n>/<timestamp>/), so the declared prefix and the
    # flywheel's own name are what the template's value controls.
    data_lake_uri = props["DataLakeS3Uri"]
    parsed = urlparse(data_lake_uri)
    segments = parsed.path.strip("/").split("/")
    assert (parsed.scheme, parsed.netloc, segments[:2]) == (
        "s3", outputs["BucketName"], ["datalake", flywheel_name]
    ), (
        f"expected DataLakeS3Uri under s3://<BucketName>/datalake/{flywheel_name}/, "
        f"got {data_lake_uri!r}"
    )
    assert len(segments) > 2 and segments[2].startswith("schemaVersion="), (
        f"expected a schemaVersion=<n> segment after the flywheel name, got {data_lake_uri!r}"
    )
    assert props["ModelType"] == "DOCUMENT_CLASSIFIER", (
        f"expected ModelType 'DOCUMENT_CLASSIFIER', got {props['ModelType']!r}"
    )
    task_config = props["TaskConfig"]
    assert task_config["LanguageCode"] == "en", (
        f"expected TaskConfig.LanguageCode 'en', got {task_config['LanguageCode']!r}"
    )
    doc_config = task_config["DocumentClassificationConfig"]
    assert doc_config["Mode"] == "MULTI_CLASS", (
        f"expected DocumentClassificationConfig.Mode 'MULTI_CLASS', got {doc_config['Mode']!r}"
    )
    assert sorted(doc_config["Labels"]) == ["NEGATIVE", "POSITIVE"], (
        f"expected DocumentClassificationConfig.Labels ['NEGATIVE', 'POSITIVE'], "
        f"got {doc_config['Labels']!r}"
    )
    tag_list = comprehend.list_tags_for_resource(ResourceArn=want_arn)["Tags"]
    user_tags = {t["Key"]: t["Value"] for t in tag_list if not t["Key"].startswith("aws:")}
    # The stack-level sim2real tag, when CloudFormation propagates it, carries the stack name.
    assert user_tags.pop("sim2real", stack_name) == stack_name, f"flywheel tags {tag_list!r}"
    assert user_tags == {"sim2real-check": CHECK}, (
        f"expected the flywheel's template Tags {{'sim2real-check': {CHECK!r}}}, got {user_tags!r}"
    )

    _empty_data_lake(cfn, s3, stack_id)
    delete_stack(cfn, stack_id)
    _stack_gone = ("ValidationError", f"Stack with id {stack_name} does not exist")
    expect_error(lambda: cfn.describe_stacks(StackName=stack_name), *_stack_gone)
    expect_error(lambda: comprehend.describe_flywheel(FlywheelArn=want_arn), *_FLYWHEEL_NOT_FOUND)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
