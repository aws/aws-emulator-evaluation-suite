"""cfn-personalize-metric-attribution-invalid-expression-rejected-leaving-valid-attribution."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-personalize-metric-attribution-invalid-expression-rejected-leaving-valid-attribution"
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

_REJECTED = (
    "Expression must be of the form SUM(ITEMS.FIELD), SUM(INTERACTIONS.FIELD), or SAMPLECOUNT() "
    "(Service: Personalize; Operation: CreateMetricAttribution; Status Code: 400; Error Code: "
    "InvalidInputException; Request ID: <id>)",
    "InvalidRequest",
)
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


@tags("axis:rejection", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A Personalize MetricAttribution whose Expression is not a documented form is refused.

    The stack rolls back with Personalize's validation message and lists no such attribution,
    while the same template with SAMPLECOUNT() deploys an ACTIVE attribution with that metric.
    """
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    personalize = ctx.client("personalize")
    s3 = ctx.client("s3")
    sides = {}
    for side in ("a", "b"):
        sides[side] = (ctx.unique_name(f"sim2real-behav-pz-ma-bucket-{side}-").lower(),
                       ctx.unique_name(f"sim2real-behav-pz-dg-{side}-"),
                       ctx.unique_name(f"sim2real-behav-pz-schema-{side}-"),
                       ctx.unique_name(f"sim2real-behav-pz-ds-{side}-"),
                       ctx.unique_name(f"sim2real-behav-pz-ma-{side}-"))

    # Both stacks deploy at once; the control (a) is waited on after the rejection (b).
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-cfn-pzmabad-ok-"),
                           _template(*sides["a"], "SAMPLECOUNT()"),
                           Capabilities=["CAPABILITY_IAM"])
    ctx.on_cleanup(lambda: _empty_bucket(s3, sides["a"][0]))
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-cfn-pzmabad-bad-"),
                          _template(*sides["b"], "COUNT(click)"),
                          Capabilities=["CAPABILITY_IAM"])
    ctx.on_cleanup(lambda: _empty_bucket(s3, sides["b"][0]))

    status = wait_stack(cfn, bad_id, timeout_s=600.0)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    reason = failed_reason(stack_events(cfn, bad_id), "MetricAttribution")
    got = handler_reason(reason, ctx.account, *sides["b"])
    assert got == _REJECTED, f"handler reason {got!r}, expected {_REJECTED!r}"
    # Rollback absence through Personalize: no attribution of that name in the account.
    listed = [m for m in paginate(personalize, "list_metric_attributions", "metricAttributions")
              if m["name"] == sides["b"][4]]
    assert listed == [], f"Personalize lists the rejected attribution: {listed!r}"

    # Positive control: same template, the one property given a VALID value.
    status = wait_stack(cfn, good_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    outputs = stack_outputs(cfn, good_id)
    _read_role(iam, outputs["RoleArn"], good_id.split(":")[1], sides["a"][0])
    ma_arn = outputs["MetricAttributionRef"]
    ma = personalize.describe_metric_attribution(metricAttributionArn=ma_arn)["metricAttribution"]
    assert (ma["name"], ma["status"]) == (sides["a"][4], "ACTIVE"), f"control reads {ma!r}"
    metrics = paginate(personalize, "list_metric_attribution_metrics", "metrics",
                       metricAttributionArn=ma_arn)
    want = [{"eventType": "CLICK", "metricName": "CLICKSAMPLECOUNT", "expression": "SAMPLECOUNT()"}]
    assert metrics == want, f"control metrics read {metrics!r}, expected {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
