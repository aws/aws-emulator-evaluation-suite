"""deploy-lambda-microvm-image-invalid-architecture-rejected-and-rolled-back."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-lambda-microvm-image-invalid-architecture-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "iam", "lambda-microvms", "s3"]

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


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


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

_BASE_IMAGE = "microvm-image:al2023-1"
_BASE_IMAGE_VERSION = "3"
_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}


def _app_zip() -> bytes:
    """A one-file build context: a Dockerfile that runs a real, idle container."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(
            "Dockerfile",
            "FROM public.ecr.aws/docker/library/busybox:1.36\nCMD [\"sleep\", \"3600\"]\n",
        )
    return buf.getvalue()


def _template(image_name, role_name, architecture):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"Bucket": {"Type": "String"}},
        "Resources": {
            "BuildRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name,
                    "AssumeRolePolicyDocument": _TRUST,
                    "Policies": [{"PolicyName": "build", "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {"Effect": "Allow", "Action": ["s3:GetObject"],
                             "Resource": {"Fn::Sub": "arn:${AWS::Partition}:s3:::${Bucket}/app.zip"}},
                            {"Effect": "Allow",
                             "Action": ["logs:CreateLogGroup", "logs:CreateLogStream",
                                        "logs:PutLogEvents"],
                             "Resource": {"Fn::Sub":
                                          "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:*"}},
                        ],
                    }}],
                    "Tags": [{"Key": "sim2real-mv", "Value": image_name}],
                },
            },
            "Image": {
                "Type": "AWS::Lambda::MicrovmImage",
                "Properties": {
                    "Name": image_name,
                    "BaseImageArn": {"Fn::Sub": "arn:${AWS::Partition}:lambda:${AWS::Region}:aws:"
                                                + _BASE_IMAGE},
                    "BaseImageVersion": _BASE_IMAGE_VERSION,
                    "BuildRoleArn": {"Fn::GetAtt": ["BuildRole", "Arn"]},
                    "Description": "sim2real microvm image",
                    "CodeArtifact": {"Uri": {"Fn::Sub": "s3://${Bucket}/app.zip"}},
                    "Logging": {"Disabled": True},
                    "EgressNetworkConnectors": [],
                    "CpuConfigurations": [{"Architecture": architecture}],
                    "Resources": [{"MinimumMemoryInMiB": 512}],
                    "AdditionalOsCapabilities": [],
                    "Hooks": {},
                    "EnvironmentVariables": [{"Key": "SIM2REAL", "Value": image_name}],
                    "Tags": [{"Key": "sim2real-mv", "Value": image_name}],
                },
            },
        },
        "Outputs": {
            "ImageArn": {"Value": {"Ref": "Image"}},
            "ImageState": {"Value": {"Fn::GetAtt": ["Image", "State"]}},
            "ImageLatestActiveVersion": {
                "Value": {"Fn::GetAtt": ["Image", "LatestActiveImageVersion"]}},
        },
    })


def _code_bucket(ctx, s3, name):
    """A tagged bucket holding the build context; its cleanup empties and deletes it."""
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    # Registered first: a bucket S3 created is deleted even if the call raises.
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": name}]})
    s3.put_object(Bucket=name, Key="app.zip", Body=_app_zip())


def _delete_bucket(s3, bucket):
    """Delete every object version, then the bucket; a bucket already gone is done."""
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objs = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                    for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
            if objs:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _listed(mv, name):
    """``(imageArn, state)`` of every image lambda-microvms lists under exactly ``name``."""
    return [(i["imageArn"], i["state"]) for i in paginate(mv, "list_microvm_images", "items",
                                                          nameFilter=name) if i["name"] == name]


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Lambda MicrovmImage with an Architecture outside the enum fails validation.

    Early validation refuses CpuConfigurations Architecture ARM64 and nothing is created, while
    the same template with ARM_64 builds an image whose version reads back ARM_64.
    """
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    mv = ctx.client("lambda-microvms")
    cfn = ctx.client("cloudformation")
    bucket = ctx.unique_name("sim2real-mvimgarch-")
    good_role, good_image = (ctx.unique_name("sim2real-mvimgarch-ok-role-"),
                             ctx.unique_name("sim2real-mvimgarch-ok-img-"))
    bad_role, bad_image = (ctx.unique_name("sim2real-mvimgarch-bad-role-"),
                           ctx.unique_name("sim2real-mvimgarch-bad-img-"))
    params = [{"ParameterKey": "Bucket", "ParameterValue": bucket}]

    _code_bucket(ctx, s3, bucket)
    # Positive control: the same template with Architecture given a VALID value.
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-mvimgarch-okstk-"),
                           _template(good_image, good_role, "ARM_64"), Parameters=params,
                           Capabilities=["CAPABILITY_NAMED_IAM"])
    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-mvimgarch-badstk-"),
                          _template(bad_image, bad_role, "ARM64"), Parameters=params,
                          Capabilities=["CAPABILITY_NAMED_IAM"])

    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    # CpuConfigurations is write-only, so CloudFormation redacts the offending value itself.
    rows = [r for r in validation_rows(cfn, bad_id) if r[3] == "FAIL"]
    assert rows == [("Image", "PROPERTY_VALIDATION", "FAILED", "FAIL",
                     "<REDACTED> is not a valid enum value. Supported values: [ARM_64, X86_64]",
                     "/Resources/Image/Properties/CpuConfigurations/0/Architecture")], (
        f"validation refusals {rows!r}"
    )
    # Nothing was created: no image under the name and no build role, before any delete.
    assert _listed(mv, bad_image) == [], f"rejected image listed: {_listed(mv, bad_image)!r}"
    role_gone = ("NoSuchEntity", f"The role with name {bad_role} cannot be found.")
    expect_error(lambda: iam.get_role(RoleName=bad_role), *role_gone)

    status = wait_stack(cfn, good_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    ref = stack_outputs(cfn, good_id)["ImageArn"]
    assert _listed(mv, good_image) == [(ref, "CREATED")], f"control image {ref!r} not listed"
    image = mv.get_microvm_image(imageIdentifier=ref)
    version = mv.get_microvm_image_version(imageIdentifier=ref,
                                           imageVersion=image["latestActiveImageVersion"])
    assert (version["cpuConfigurations"], version["state"]) == (
        [{"architecture": "ARM_64"}], "SUCCESSFUL"), f"control version {version!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
