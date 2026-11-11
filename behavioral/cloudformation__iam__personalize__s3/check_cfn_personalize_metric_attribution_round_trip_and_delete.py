"""cfn-personalize-metric-attribution-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-personalize-metric-attribution-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "iam", "personalize", "s3"]

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

_INTERACTIONS_SCHEMA = {
    "type": "record",
    "name": "Interactions",
    "namespace": "com.amazonaws.personalize.schema",
    "fields": [
        {"name": "USER_ID", "type": "string"},
        {"name": "ITEM_ID", "type": "string"},
        {"name": "TIMESTAMP", "type": "long"},
        {"name": "EVENT_TYPE", "type": "string"},
    ],
    "version": "1.0",
}
_ROLE_POLICY = "metric-attribution-access"


def _empty_bucket(s3, bucket_name):
    """Personalize writes attribution metrics into the bucket; CloudFormation deletes only an
    empty bucket. A bucket that no longer exists (NoSuchBucket) has nothing to empty."""
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket_name):
            objects = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objects:
                s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objects})
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _bucket_policy_doc(bucket_name):
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "PersonalizeS3Access",
            "Effect": "Allow",
            "Principal": {"Service": "personalize.amazonaws.com"},
            "Action": ["s3:GetObject", "s3:ListBucket", "s3:PutObject"],
            "Resource": [
                {"Fn::Sub": f"arn:${{AWS::Partition}}:s3:::{bucket_name}"},
                {"Fn::Sub": f"arn:${{AWS::Partition}}:s3:::{bucket_name}/*"},
            ],
        }],
    }


def _role_policy(partition, bucket_name):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket", "s3:PutObject"],
             "Resource": [f"arn:{partition}:s3:::{bucket_name}",
                          f"arn:{partition}:s3:::{bucket_name}/*"]},
            {"Effect": "Allow", "Action": "cloudwatch:PutMetricData", "Resource": "*"},
        ],
    }


def _template(bucket_name, dg_name, schema_name, ds_name, ma_name, expression, *, with_ma=True):
    resources = {
        "Bucket": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": bucket_name}},
        "BucketPolicy": {
            "Type": "AWS::S3::BucketPolicy",
            "Properties": {"Bucket": {"Ref": "Bucket"},
                           "PolicyDocument": _bucket_policy_doc(bucket_name)},
        },
        "Role": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow",
                                   "Principal": {"Service": "personalize.amazonaws.com"},
                                   "Action": "sts:AssumeRole"}],
                },
                "Policies": [{
                    "PolicyName": _ROLE_POLICY,
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {"Effect": "Allow",
                             "Action": ["s3:GetObject", "s3:ListBucket", "s3:PutObject"],
                             "Resource": [{"Fn::GetAtt": ["Bucket", "Arn"]},
                                          {"Fn::Sub": ["${BucketArn}/*", {
                                              "BucketArn": {"Fn::GetAtt": ["Bucket", "Arn"]}}]}]},
                            {"Effect": "Allow", "Action": "cloudwatch:PutMetricData",
                             "Resource": "*"},
                        ],
                    },
                }],
            },
        },
        "DatasetGroup": {"Type": "AWS::Personalize::DatasetGroup", "Properties": {"Name": dg_name}},
        "Schema": {
            "Type": "AWS::Personalize::Schema",
            "Properties": {"Name": schema_name, "Schema": json.dumps(_INTERACTIONS_SCHEMA)},
        },
        "Dataset": {
            "Type": "AWS::Personalize::Dataset",
            "Properties": {
                "Name": ds_name,
                "DatasetType": "Interactions",
                "DatasetGroupArn": {"Ref": "DatasetGroup"},
                "SchemaArn": {"Ref": "Schema"},
            },
        },
    }
    outputs = {
        "DatasetGroupArn": {"Value": {"Ref": "DatasetGroup"}},
        "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
    }
    if with_ma:
        resources["MetricAttribution"] = {
            "Type": "AWS::Personalize::MetricAttribution",
            "DependsOn": ["Dataset", "BucketPolicy"],
            "Properties": {
                "Name": ma_name,
                "DatasetGroupArn": {"Ref": "DatasetGroup"},
                "Metrics": [{"EventType": "click", "MetricName": "clickSampleCount",
                             "Expression": expression}],
                "MetricsOutputConfig": {
                    "S3DataDestination": {"Path": {"Fn::Sub": "s3://${Bucket}/metrics/"}},
                    "RoleArn": {"Fn::GetAtt": ["Role", "Arn"]},
                },
            },
        }
        outputs["MetricAttributionRef"] = {"Value": {"Ref": "MetricAttribution"}}
        outputs["MetricAttributionStatus"] = {
            "Value": {"Fn::GetAtt": ["MetricAttribution", "Status"]}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09", "Resources": resources, "Outputs": outputs,
    })


def _read_role(iam, role_arn, partition, bucket_name):
    """The stack's role answers in IAM with its inline policy exactly as templated."""
    name = role_arn.rsplit("/", 1)[1]
    assert iam.get_role(RoleName=name)["Role"]["Arn"] == role_arn, f"role {role_arn!r}"
    doc = iam.get_role_policy(RoleName=name, PolicyName=_ROLE_POLICY)["PolicyDocument"]
    assert doc == _role_policy(partition, bucket_name), f"inline policy reads {doc!r}"


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Personalize MetricAttribution reads back through Personalize exactly.

    Ref matches the attribution Personalize lists for its dataset group with every templated
    property; an update dropping it removes it while the group answers, then the stack goes.
    """
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    personalize = ctx.client("personalize")
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-pz-ma-bucket-").lower()
    names = (bucket, ctx.unique_name("sim2real-behav-pz-dg-"),
             ctx.unique_name("sim2real-behav-pz-schema-"), ctx.unique_name("sim2real-behav-pz-ds-"))
    ma_name = ctx.unique_name("sim2real-behav-pz-ma-")

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-cfn-pzma-"),
                            _template(*names, ma_name, "SAMPLECOUNT()"),
                            Capabilities=["CAPABILITY_IAM"])
    ctx.on_cleanup(lambda: _empty_bucket(s3, bucket))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]
    dg_arn = outputs["DatasetGroupArn"]
    _read_role(iam, outputs["RoleArn"], partition, bucket)

    # Ref against an independent read: the attributions listed for the group, every page.
    listed = [(m["metricAttributionArn"], m["name"]) for m in paginate(
        personalize, "list_metric_attributions", "metricAttributions", datasetGroupArn=dg_arn)]
    assert listed == [(outputs["MetricAttributionRef"], ma_name)], (
        f"Personalize lists {listed!r}; Ref is {outputs['MetricAttributionRef']!r}"
    )
    ma_arn = listed[0][0]
    ma = personalize.describe_metric_attribution(metricAttributionArn=ma_arn)["metricAttribution"]
    got = (ma["name"], ma["datasetGroupArn"], ma["status"], ma["metricsOutputConfig"]["roleArn"],
           ma["metricsOutputConfig"]["s3DataDestination"]["path"])
    want = (ma_name, dg_arn, "ACTIVE", outputs["RoleArn"], f"s3://{bucket}/metrics/")
    assert got == want, f"metric attribution reads {got!r}, expected {want!r}"
    assert outputs["MetricAttributionStatus"] == ma["status"], f"GetAtt Status {outputs!r}"
    # Personalize upper-cases eventType and metricName on read-back; the expression is verbatim.
    metrics = paginate(personalize, "list_metric_attribution_metrics", "metrics",
                       metricAttributionArn=ma_arn)
    want = [{"eventType": "CLICK", "metricName": "CLICKSAMPLECOUNT", "expression": "SAMPLECOUNT()"}]
    assert metrics == want, f"metrics read {metrics!r}, expected {want!r}"

    # Child before parent: an update drops only the attribution; its dataset group answers.
    cfn.update_stack(StackName=stack_id, Capabilities=["CAPABILITY_IAM"],
                     TemplateBody=_template(*names, ma_name, "SAMPLECOUNT()", with_ma=False))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "UPDATE_COMPLETE", f"attribution-removing update ended {status!r}"
    until_raises(lambda: personalize.describe_metric_attribution(metricAttributionArn=ma_arn),
                 timeout_s=180.0)
    ma_gone = ("ResourceNotFoundException",
               f"The given metric attribution does not exist: {ma_arn}")
    expect_error(lambda: personalize.describe_metric_attribution(metricAttributionArn=ma_arn),
                 *ma_gone)
    group = personalize.describe_dataset_group(datasetGroupArn=dg_arn)["datasetGroup"]
    assert group["datasetGroupArn"] == dg_arn, f"the dataset group reads {group!r}"

    _empty_bucket(s3, bucket)
    delete_stack(cfn, stack_id)
    until_raises(lambda: personalize.describe_dataset_group(datasetGroupArn=dg_arn),
                 timeout_s=180.0)
    group_gone = ("ResourceNotFoundException", f"The given dataset group does not exist: {dg_arn}")
    expect_error(lambda: personalize.describe_dataset_group(datasetGroupArn=dg_arn), *group_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
