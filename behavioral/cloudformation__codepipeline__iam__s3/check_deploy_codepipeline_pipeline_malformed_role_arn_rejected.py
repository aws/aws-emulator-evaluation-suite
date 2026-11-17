"""deploy-codepipeline-pipeline-malformed-role-arn-rejected."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-codepipeline-pipeline-malformed-role-arn-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "codepipeline", "iam", "s3"]

_TERMINAL = frozenset(
    {
        "CREATE_COMPLETE",
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "DELETE_COMPLETE",
        "DELETE_FAILED",
        "UPDATE_COMPLETE",
        "UPDATE_ROLLBACK_COMPLETE",
        "UPDATE_FAILED",
        "UPDATE_ROLLBACK_FAILED",
        "IMPORT_COMPLETE",
        "IMPORT_ROLLBACK_COMPLETE",
        "IMPORT_ROLLBACK_FAILED",
    }
)
_DELETE_BUDGET_S = 600.0
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)
_ARTIFACT_ACTIONS = [
    "s3:GetObject",
    "s3:GetObjectVersion",
    "s3:PutObject",
    "s3:GetBucketVersioning",
    "s3:ListBucket",
]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0, ctx=None):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it. With
    ``ctx`` the deadline is capped by the run budget, and a budget-ended wait is not graded."""
    if ctx is not None:
        timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(
                    f"stack {stack_id} reaching a terminal status: the run budget ended first; "
                    f"not graded"
                )
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice."""
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in (
        "DELETE_IN_PROGRESS",
        "REVIEW_IN_PROGRESS",
    ):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(
        cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, deadline - time.monotonic()
    )
    if status != "DELETE_COMPLETE":
        events = stack_events(cf, stack_id)
        starts = [
            i
            for i, e in enumerate(events)
            if e.get("PhysicalResourceId") == stack_id
            and e["ResourceStatus"] == "DELETE_IN_PROGRESS"
        ]
        failed = [
            (e["LogicalResourceId"], e.get("ResourceStatusReason"))
            for e in events[starts[-1] if starts else 0 :]
            if e["ResourceStatus"] == "DELETE_FAILED"
        ]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns."""
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                "ValidationError",
                f"Stack with id {name} does not exist",
            ):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name>; cleanup registered before the call."""
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``."""
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [
        e.get("ResourceStatusReason")
        for e in events
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status
    ]
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


def _role_not_assumable(partition: str) -> tuple[str, str]:
    """The masked handler reason of a Pipeline whose role CodePipeline cannot assume."""
    return (
        "CodePipeline is not authorized to perform AssumeRole on role "
        f"arn:{partition}:iam::<account>:role/<name> (Service: CodePipeline, "
        "Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
        "GeneralServiceException",
    )


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (
            e.get("LogicalResourceId"),
            e.get("ValidationName"),
            e.get("ValidationStatus"),
            e.get("ValidationFailureMode"),
            e.get("ValidationStatusReason"),
            e.get("ValidationPath"),
        )
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


def _create_stack_retrying_role_propagation(
    ctx, cf, stack: str, template: str, role_name: str, *, deadline_s: float = 90.0, **kw
) -> str:
    """CreateStack where the Pipeline's RoleArn trust is freshly created: IAM's AssumeRole trust
    exposes no condition to poll, so a rollback whose Pipeline reason is exactly
    ``_role_not_assumable`` for ``role_name`` is retried by recreating the stack, bounded by
    ``deadline_s``. Returns the CREATE_COMPLETE stack's id."""
    deadline = time.monotonic() + _budget_s(ctx, deadline_s)
    while True:
        stack_id = create_stack(ctx, cf, stack, template, **kw)
        status = wait_stack(cf, stack_id, ctx=ctx)
        if status == "CREATE_COMPLETE":
            return stack_id
        events = stack_events(cf, stack_id)
        reasons = [
            e.get("ResourceStatusReason")
            for e in events
            if e["LogicalResourceId"] == "Pipeline" and e["ResourceStatus"] == "CREATE_FAILED"
        ]
        is_propagation = (
            status == "ROLLBACK_COMPLETE"
            and len(reasons) == 1
            and _HANDLER_REASON.match(reasons[0] or "") is not None
            and handler_reason(reasons[0], ctx.account, role_name)
            == _role_not_assumable(stack_id.split(":")[1])
        )
        if not is_propagation or time.monotonic() > deadline:
            raise AssertionError(
                f"stack {stack!r} ended {status!r}, expected CREATE_COMPLETE: {reasons!r}"
            )
        delete_stack(cf, stack_id)
        time.sleep(5)


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


def _template(role_arn) -> str:
    """A pipeline whose top-level RoleArn is the given value, otherwise minimal and valid."""
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {
                "BucketName": {"Type": "String"},
                "PipelineName": {"Type": "String"},
                "RoleArn": {"Type": "String"},
            },
            "Resources": {
                "Pipeline": {
                    "Type": "AWS::CodePipeline::Pipeline",
                    "Properties": {
                        "Name": {"Ref": "PipelineName"},
                        "RoleArn": {"Ref": "RoleArn"},
                        "ArtifactStore": {"Type": "S3", "Location": {"Ref": "BucketName"}},
                        "Stages": [
                            {
                                "Name": "Source",
                                "Actions": [
                                    {
                                        "Name": "SourceAction",
                                        "ActionTypeId": {
                                            "Category": "Source",
                                            "Owner": "AWS",
                                            "Provider": "S3",
                                            "Version": "1",
                                        },
                                        "OutputArtifacts": [{"Name": "SourceOutput"}],
                                        "Configuration": {
                                            "S3Bucket": {"Ref": "BucketName"},
                                            "S3ObjectKey": "source.zip",
                                            "PollForSourceChanges": False,
                                        },
                                        "RunOrder": 1,
                                    }
                                ],
                            },
                            {
                                "Name": "Approve",
                                "Actions": [
                                    {
                                        "Name": "ManualApproval",
                                        "ActionTypeId": {
                                            "Category": "Approval",
                                            "Owner": "AWS",
                                            "Provider": "Manual",
                                            "Version": "1",
                                        },
                                        "RunOrder": 1,
                                    }
                                ],
                            },
                        ],
                    },
                },
            },
            "Outputs": {
                "PipelineRef": {"Value": {"Ref": "Pipeline"}},
            },
        }
    )


def _create_bucket(ctx, s3, logical: str) -> str:
    """A tagged bucket; its delete is registered before the create."""
    bucket = ctx.unique_name(f"sim2real-cppiprl-{logical}-").lower().replace("_", "-")

    def _cleanup() -> None:
        try:
            objs = [
                {"Key": v["Key"], "VersionId": v["VersionId"]}
                for key in ("Versions", "DeleteMarkers")
                for v in paginate(s3, "list_object_versions", key, Bucket=bucket)
            ]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
            return
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": bucket}]})
    return bucket


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:deploy",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """A CloudFormation AWS::CodePipeline::Pipeline whose RoleArn does not match the IAM role ARN
    pattern fails stack validation on RoleArn's pattern and rolls back with no pipeline created;
    the same template with a real role ARN still reaches CREATE_COMPLETE.
    """
    s3 = ctx.client("s3")
    cf = ctx.client("cloudformation")
    cp = ctx.client("codepipeline")

    bucket = _create_bucket(ctx, s3, "src")

    # Refusal: RoleArn is a plain string, not an IAM role ARN.
    bad_name = ctx.unique_name("sim2real-cppiprl-bad-")
    bad_stack = ctx.unique_name("sim2real-cppiprl-bad-stack-")
    bad_stack_id = create_stack(
        ctx,
        cf,
        bad_stack,
        _template("not-an-arn"),
        Parameters=[
            {"ParameterKey": "BucketName", "ParameterValue": bucket},
            {"ParameterKey": "PipelineName", "ParameterValue": bad_name},
            {"ParameterKey": "RoleArn", "ParameterValue": "not-an-arn"},
        ],
    )
    bad_status = wait_stack(cf, bad_stack_id, ctx=ctx)
    assert bad_status == "ROLLBACK_COMPLETE", (
        f"a malformed RoleArn ended {bad_status!r}, expected ROLLBACK_COMPLETE"
    )
    events = stack_events(cf, bad_stack_id)
    reason = failed_reason(events, bad_stack)
    assert reason == (
        "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of "
        "issues with resource and property details, resolve each error, then retry the operation."
    ), f"unexpected CREATE_FAILED reason for a malformed RoleArn: {reason!r}"
    failed_rows = [
        e
        for e in events
        if e["LogicalResourceId"] == bad_stack and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert failed_rows[0].get("DetailedStatus") == "VALIDATION_FAILED", (
        f"expected DetailedStatus VALIDATION_FAILED, got {failed_rows[0].get('DetailedStatus')!r}"
    )
    found = validation_rows(cf, bad_stack_id)
    want = [
        (
            "Pipeline",
            "PROPERTY_VALIDATION",
            "FAILED",
            "FAIL",
            "Property value [not-an-arn] does not match pattern: arn:aws(-[\\w]+)*:iam::[0-9]{12}:role/.*",
            "/Resources/Pipeline/Properties/RoleArn",
        )
    ]
    assert found == want, f"validation errors of the create: expected {want!r}, got {found!r}"
    pipeline_rows = [e for e in events if e["LogicalResourceId"] == "Pipeline"]
    assert pipeline_rows == [], (
        f"expected the Pipeline resource never to be attempted, got events {pipeline_rows!r}"
    )

    pipeline_gone = (
        "PipelineNotFoundException",
        f"Account '{ctx.account}' does not have a pipeline with name '{bad_name}'",
    )
    expect_error(lambda: cp.get_pipeline(name=bad_name), *pipeline_gone)
    delete_stack(cf, bad_stack_id)

    # Positive control: the same template with a real IAM role ARN still succeeds.
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cppiprl-role-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "codepipeline.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-cppiprl-policy-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": _ARTIFACT_ACTIONS,
                        "Resource": [
                            f"arn:{iam.meta.partition}:s3:::{bucket}",
                            f"arn:{iam.meta.partition}:s3:::{bucket}/*",
                        ],
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]

    good_name = ctx.unique_name("sim2real-cppiprl-ok-")
    good_stack = ctx.unique_name("sim2real-cppiprl-ok-stack-")
    good_stack_id = _create_stack_retrying_role_propagation(
        ctx,
        cf,
        good_stack,
        _template(role_arn),
        role_name,
        Parameters=[
            {"ParameterKey": "BucketName", "ParameterValue": bucket},
            {"ParameterKey": "PipelineName", "ParameterValue": good_name},
            {"ParameterKey": "RoleArn", "ParameterValue": role_arn},
        ],
    )
    good_status = wait_stack(cf, good_stack_id, ctx=ctx)
    assert good_status == "CREATE_COMPLETE", (
        f"a well-formed RoleArn ended {good_status!r}, expected CREATE_COMPLETE"
    )
    declared = cp.get_pipeline(name=good_name)["pipeline"]
    assert declared["roleArn"] == role_arn, (
        f"GetPipeline roleArn is {declared['roleArn']!r}, expected the template's {role_arn!r}"
    )
    delete_stack(cf, good_stack_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
