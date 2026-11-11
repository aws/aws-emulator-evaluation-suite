"""cdk-s3-auto-delete-objects-empties-past-destroy-manual-bucket-blocks-on-bucketnotempty."""
from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cdk-s3-auto-delete-objects-empties-past-destroy-manual-bucket-blocks-on-bucketnotempty"
GROUP = "deploy"
SERVICES = ["cloudformation"]

_DEPLOY_TIMEOUT_S = 600.0
_DESTROY_TIMEOUT_S = 420.0
_TEARDOWN_DEADLINE_S = 420.0

_APP = "cdk_s3_autodelete"


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:deploy",
      "concern:negative-classes", "concern:representation", "dp:api", "plane:control",
      "plane:data")
def run(ctx) -> None:
    """A Bucket with `auto_delete_objects=True` empties itself and is gone after `cdk destroy`.

    Its twin bucket with no `auto_delete_objects`, holding one object, blocks the stack delete
    with BucketNotEmpty, then deletes clean once that bucket is emptied by hand.

    Reference: https://docs.aws.amazon.com/cdk/api/v2/docs/aws-cdk-lib.aws_s3.Bucket.html
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    account = ctx.client("sts").get_caller_identity()["Account"]
    s3 = ctx.client("s3")
    cfn = ctx.client("cloudformation")

    stack = ctx.unique_name("sim2real-cdkautodel-")
    app_context = {"account": account, "region": ctx.region, "stack_name": stack}
    work = _stage_app(ctx, _APP)

    auto_bucket: str | None = None
    manual_bucket: str | None = None
    handler_log_group: str | None = None

    try:
        # ---- the construct-level claim, asserted on the template BEFORE anything is deployed ----
        template = _synth_doc(ctx, work, stack, app_context, out="out-1",
                              timeout_s=_DEPLOY_TIMEOUT_S)
        buckets = _resources_of_type(template, "AWS::S3::Bucket")
        assert len(buckets) == 2, (
            f"the synthesised template holds {len(buckets)} S3 buckets ({sorted(buckets)!r}), "
            f"expected exactly 2 — the auto/manual contrast needs both"
        )
        custom_resources = _resources_of_type(template, "Custom::S3AutoDeleteObjects")
        assert len(custom_resources) == 1, (
            f"expected exactly 1 Custom::S3AutoDeleteObjects resource, template has "
            f"{len(custom_resources)} ({sorted(custom_resources)!r}) — the manual bucket must "
            f"get none"
        )
        handlers = _resources_of_type(template, "AWS::Lambda::Function")
        assert len(handlers) == 1, (
            f"expected exactly 1 Lambda function (the auto-delete handler), template has "
            f"{len(handlers)} ({sorted(handlers)!r})"
        )
        handler_logical_id = next(iter(handlers))
        assert "ZipFile" in handlers[handler_logical_id]["Properties"]["Code"], (
            f"the auto-delete handler's Code property is "
            f"{handlers[handler_logical_id]['Properties']['Code']!r}, expected an inline "
            f"'ZipFile' — a published asset would need `cdk bootstrap`, which this app must not"
        )

        # ---- deploy, and seed BOTH buckets with one object each ---------------------------------
        _cdk(ctx, work, ["deploy", stack, "--require-approval", "never"], app_context,
             timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)
        deployed = {
            r["LogicalResourceId"]: r
            for r in cfn.describe_stack_resources(StackName=stack)["StackResources"]
        }
        assert handler_logical_id in deployed, (
            f"the deployed stack {stack!r} lists no {handler_logical_id!r} handler; resources: "
            f"{sorted(deployed)!r}"
        )
        handler_log_group = f"/aws/lambda/{deployed[handler_logical_id]['PhysicalResourceId']}"
        outputs = _stack_outputs(ctx, stack)
        auto_bucket = outputs["AutoBucketName"]
        manual_bucket = outputs["ManualBucketName"]
        assert auto_bucket != manual_bucket, f"both outputs named the same bucket {auto_bucket!r}"
        manual_logical = _logical_id_for_bucket(buckets, deployed, manual_bucket)
        auto_logical = _logical_id_for_bucket(buckets, deployed, auto_bucket)

        auto_key = ctx.unique_name("auto-key-")
        auto_body = ctx.unique_name("auto-body-").encode()
        manual_key = ctx.unique_name("manual-key-")
        manual_body = ctx.unique_name("manual-body-").encode()
        s3.put_object(Bucket=auto_bucket, Key=auto_key, Body=auto_body)
        s3.put_object(Bucket=manual_bucket, Key=manual_key, Body=manual_body)
        assert s3.get_object(Bucket=auto_bucket, Key=auto_key)["Body"].read() == auto_body, (
            f"object just written to the auto bucket {auto_bucket!r} does not read back"
        )
        assert s3.get_object(Bucket=manual_bucket, Key=manual_key)["Body"].read() == manual_body, (
            f"object just written to the manual bucket {manual_bucket!r} does not read back"
        )

        # ---- first destroy: must be REFUSED, because the manual bucket is not empty -------------
        rc, out = _cdk(ctx, work, ["destroy", stack, "--force"], app_context,
                       timeout_s=_DESTROY_TIMEOUT_S, expect_rc=None)
        assert rc != 0, (
            f"`cdk destroy` exited 0 while the manual bucket {manual_bucket!r} still held an "
            f"object — the delete should have been refused. Output tail: {out[-1000:]!r}"
        )

        status, resources = _wait_stack_terminal(ctx, stack, timeout_s=_DESTROY_TIMEOUT_S)
        assert status == "DELETE_FAILED", (
            f"stack {stack!r} reached {status!r} after the first destroy attempt, expected "
            f"DELETE_FAILED because the manual bucket holds an object"
        )
        assert manual_logical in resources, (
            f"the DELETE_FAILED stack {stack!r} no longer lists the manual bucket "
            f"{manual_logical!r}; resources: "
            f"{ {lid: r['ResourceStatus'] for lid, r in resources.items()}!r}"
        )
        manual_resource = resources[manual_logical]
        assert manual_resource["ResourceStatus"] == "DELETE_FAILED", (
            f"the manual bucket's resource {manual_logical!r} is {manual_resource['ResourceStatus']!r} "
            f"on the DELETE_FAILED stack, expected DELETE_FAILED"
        )
        assert "The bucket you tried to delete is not empty" in manual_resource.get(
            "ResourceStatusReason", ""
        ), (
            f"the manual bucket's DELETE_FAILED reason is "
            f"{manual_resource.get('ResourceStatusReason')!r}, expected it to carry S3's "
            f"BucketNotEmpty message"
        )
        auto_resource = resources.get(auto_logical)
        assert auto_resource is None or auto_resource["ResourceStatus"] == "DELETE_COMPLETE", (
            f"the auto bucket's resource {auto_logical!r} is "
            f"{auto_resource['ResourceStatus'] if auto_resource else None!r}, expected it to have "
            f"been deleted despite the sibling's failure"
        )

        # ---- the auto bucket is REALLY gone ------------------------------------------------------
        gone = _client_error(lambda: s3.head_bucket(Bucket=auto_bucket))
        assert gone.response["Error"]["Code"] == "404", (
            f"HeadBucket on the auto-delete bucket {auto_bucket!r} returned error code "
            f"{gone.response['Error']['Code']!r} after `cdk destroy`, expected '404' (NoSuchBucket)"
        )

        # ---- the manual bucket SURVIVED, with its object intact (positive control) --------------
        survivor_body = s3.get_object(Bucket=manual_bucket, Key=manual_key)["Body"].read()
        assert survivor_body == manual_body, (
            f"the manual bucket {manual_bucket!r} survived the failed delete but its object body "
            f"changed: got {survivor_body!r}, expected {manual_body!r}"
        )

        # ---- the raw S3 API refuses the same delete with the exact documented error --------------
        direct = _client_error(lambda: s3.delete_bucket(Bucket=manual_bucket))
        assert direct.response["Error"]["Code"] == "BucketNotEmpty", (
            f"DeleteBucket on {manual_bucket!r} returned error code "
            f"{direct.response['Error']['Code']!r}, expected 'BucketNotEmpty'"
        )
        assert direct.response["Error"]["Message"] == (
            "The bucket you tried to delete is not empty"
        ), (
            f"DeleteBucket on {manual_bucket!r} raised BucketNotEmpty with message "
            f"{direct.response['Error']['Message']!r}"
        )
        still_there = s3.get_object(Bucket=manual_bucket, Key=manual_key)["Body"].read()
        assert still_there == manual_body, (
            f"the refused DeleteBucket call on {manual_bucket!r} changed its contents"
        )

        # ---- empty the manual bucket by hand, then the SAME destroy command succeeds ------------
        s3.delete_object(Bucket=manual_bucket, Key=manual_key)
        listing = s3.list_objects_v2(Bucket=manual_bucket)
        assert listing["KeyCount"] == 0 and not listing.get("Contents"), (
            f"manual bucket {manual_bucket!r} still reports {listing['KeyCount']} key(s) "
            f"({[o['Key'] for o in listing.get('Contents', [])]!r}) after DeleteObject"
        )
        rc2, out2 = _cdk(ctx, work, ["destroy", stack, "--force"], app_context,
                         timeout_s=_DESTROY_TIMEOUT_S, expect_rc=None)
        assert rc2 == 0, (
            f"`cdk destroy` exited {rc2} once the manual bucket was emptied, expected 0 — the only "
            f"blocker was the object. Output tail: {out2[-1000:]!r}"
        )
        _assert_stack_absent(ctx, stack)
        manual_gone = _client_error(lambda: s3.head_bucket(Bucket=manual_bucket))
        assert manual_gone.response["Error"]["Code"] == "404", (
            f"HeadBucket on the emptied manual bucket {manual_bucket!r} returned error code "
            f"{manual_gone.response['Error']['Code']!r} after the second `cdk destroy`, expected "
            f"'404' (NoSuchBucket)"
        )
    finally:
        _teardown(ctx, stack, auto_bucket, manual_bucket, handler_log_group)


def _logical_id_for_bucket(buckets: dict[str, Any], deployed: dict[str, Any],
                           physical_name: str) -> str:
    """The template bucket whose deployed PhysicalResourceId is *physical_name*."""
    candidates = [lid for lid in buckets
                  if deployed.get(lid, {}).get("PhysicalResourceId") == physical_name]
    assert len(candidates) == 1, (
        f"expected exactly one template bucket deployed as {physical_name!r}, got "
        f"{candidates!r}; deployed buckets: "
        f"{ {lid: deployed.get(lid, {}).get('PhysicalResourceId') for lid in buckets}!r}"
    )
    return candidates[0]


def _wait_stack_terminal(ctx, stack: str, *, timeout_s: float) -> tuple[str, dict[str, Any]]:
    """Poll `DescribeStacks` until the stack leaves DELETE_IN_PROGRESS.

    Returns `(stack status, {logical id: resource})`. Raises if the stack was deleted outright or
    the poll times out.
    """
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last_status = "never read"
    while time.monotonic() < deadline:
        try:
            last_status = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if _is_stack_not_found(exc, stack):
                raise AssertionError(
                    f"stack {stack!r} was deleted outright, expected DELETE_FAILED because the "
                    f"manual bucket holds an object"
                ) from exc
            raise
        if last_status != "DELETE_IN_PROGRESS":
            resources = {
                r["LogicalResourceId"]: r
                for r in cfn.describe_stack_resources(StackName=stack)["StackResources"]
            }
            return last_status, resources
        time.sleep(5.0)
    raise AssertionError(
        f"stack {stack!r} did not leave DELETE_IN_PROGRESS within {timeout_s}s "
        f"(last status {last_status!r})"
    )


def _is_stack_not_found(exc: ClientError, stack: str) -> bool:
    """True only for CloudFormation's own not-found error for *stack*."""
    error = exc.response["Error"]
    return (error["Code"] == "ValidationError"
            and error["Message"] == f"Stack with id {stack} does not exist")


def _stage_app(ctx, name: str) -> Path:
    """Copy `deployments/<name>` into a temp dir so `cdk.out` never lands in the repo."""
    import shutil
    import tempfile

    source = Path(__file__).parent / "deployments" / name
    assert source.is_dir(), (
        f"the CDK app this check references is missing from disk: {source} does not exist "
        f"(artifact defect, not a missing prerequisite)"
    )
    assert (source / "app.py").is_file() and (source / "cdk.json").is_file(), (
        f"the CDK app at {source} is incomplete: app.py present="
        f"{(source / 'app.py').is_file()}, cdk.json present={(source / 'cdk.json').is_file()}"
    )
    work = Path(tempfile.mkdtemp(prefix=f"sim2real-{name}-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    staged = work / name
    shutil.copytree(source, staged, ignore=shutil.ignore_patterns(
        "cdk.out", "out-*", ".venv", "__pycache__", "node_modules"))
    return staged


def _cdk(ctx, work: Path, args: list[str], context: dict[str, str], *, timeout_s: float,
         expect_rc: int | None) -> tuple[int, str]:
    """Run the CDK CLI in *work*, returning `(returncode, stdout+stderr)`."""
    import subprocess

    ctx.verify_account_safety()
    cmd = ["cdk", *args, "--ci", "--no-version-reporting", "--no-notices", "--no-color"]
    for key, value in context.items():
        cmd += ["--context", f"{key}={value}"]
    result = subprocess.run(cmd, cwd=work, env=ctx.subprocess_env(), capture_output=True,
                            text=True, timeout=timeout_s)
    output = result.stdout + result.stderr
    if expect_rc is not None:
        assert result.returncode == expect_rc, (
            f"`cdk {' '.join(args)}` exited {result.returncode}, expected {expect_rc}; output tail: "
            f"{output[-1200:]!r}"
        )
    return result.returncode, output


def _synth_doc(ctx, work: Path, stack: str, context: dict[str, str], *, out: str,
               timeout_s: float) -> dict[str, Any]:
    """Synthesise into `<work>/<out>` and return the parsed template."""
    import json
    import shutil

    shutil.rmtree(work / out, ignore_errors=True)
    _cdk(ctx, work, ["synth", stack, "--output", out, "--quiet"], context,
         timeout_s=timeout_s, expect_rc=0)
    template = work / out / f"{stack}.template.json"
    assert template.is_file(), (
        f"`cdk synth` exited 0 but wrote no template at {template}; {out} contains "
        f"{sorted(p.name for p in (work / out).iterdir()) if (work / out).is_dir() else 'nothing'}"
    )
    return json.loads(template.read_text())


def _resources_of_type(template: dict[str, Any], type_name: str) -> dict[str, Any]:
    """Every resource of *type_name*, keyed by logical id. Hard-subscripts `Resources` on purpose."""
    return {k: v for k, v in template["Resources"].items() if v["Type"] == type_name}


def _stack_outputs(ctx, stack: str) -> dict[str, str]:
    """The deployed stack's Outputs, read from CloudFormation rather than the CLI's outputs file."""
    described = ctx.client("cloudformation").describe_stacks(StackName=stack)["Stacks"][0]
    assert described["StackStatus"] in ("CREATE_COMPLETE", "UPDATE_COMPLETE"), (
        f"stack {stack!r} is {described['StackStatus']!r}, expected CREATE_COMPLETE or "
        f"UPDATE_COMPLETE before reading its outputs"
    )
    return {o["OutputKey"]: o["OutputValue"] for o in described.get("Outputs", [])}


def _client_error(fn) -> ClientError:
    """The ClientError a call raises, for when the MESSAGE matters as well as the code."""
    try:
        fn()
    except ClientError as exc:
        return exc
    raise AssertionError("call succeeded but was expected to be refused")


def _assert_stack_absent(ctx, stack: str) -> None:
    """An independent read must report the stack gone with CloudFormation's specific code."""
    exc = _client_error(lambda: ctx.client("cloudformation").describe_stacks(StackName=stack))
    code = exc.response["Error"]["Code"]
    assert code == "ValidationError", (
        f"DescribeStacks on the deleted stack {stack!r} returned error code {code!r}, expected "
        f"'ValidationError'"
    )
    assert exc.response["Error"]["Message"] == f"Stack with id {stack} does not exist", (
        f"DescribeStacks on the deleted stack {stack!r} raised ValidationError with message "
        f"{exc.response['Error']['Message']!r}"
    )


def _empty_bucket(s3, bucket: str) -> None:
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "404"):
            raise


def _delete_bucket_if_present(s3, bucket: str | None) -> None:
    if not bucket:
        return
    _empty_bucket(s3, bucket)
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "404"):
            raise


def _delete_stack_and_wait(ctx, stack: str, *, timeout_s: float) -> None:
    """Delete (even from DELETE_FAILED), then poll until the stack is gone.

    Raises on DELETE_FAILED with each failed resource's reason, on timeout, and on any error
    other than the stack's own not-found.
    """
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack)
    except ClientError as exc:
        if _is_stack_not_found(exc, stack):
            return
        raise
    deadline = time.monotonic() + timeout_s
    last = "never read"
    while time.monotonic() < deadline:
        try:
            last = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if _is_stack_not_found(exc, stack):
                return
            raise
        if last == "DELETE_COMPLETE":
            return
        if last == "DELETE_FAILED":
            failed = {
                r["LogicalResourceId"]: r.get("ResourceStatusReason")
                for r in cfn.describe_stack_resources(StackName=stack)["StackResources"]
                if r["ResourceStatus"] == "DELETE_FAILED"
            }
            raise AssertionError(f"stack {stack!r} is DELETE_FAILED: {failed!r}")
        time.sleep(5.0)
    raise AssertionError(
        f"stack {stack!r} did not reach DELETE_COMPLETE within {timeout_s}s (last status {last!r})"
    )


def _reap_log_group(ctx, name: str, *, reads: int = 3, interval_s: float = 5.0,
                    budget_s: float = 180.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent."""
    logs = ctx.client("logs")
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group {name!r} still present after {budget_s}s of deletes; {absent} "
                    f"clean reads"
                )
            time.sleep(interval_s)


def _handler_log_group_from_stack(ctx, stack: str) -> str | None:
    """The log group of the stack's Lambda handler, or None if the stack or handler is absent."""
    try:
        listed = ctx.client("cloudformation").describe_stack_resources(
            StackName=stack)["StackResources"]
    except ClientError as exc:
        if _is_stack_not_found(exc, stack):
            return None
        raise
    names = [r["PhysicalResourceId"] for r in listed
             if r["ResourceType"] == "AWS::Lambda::Function" and r.get("PhysicalResourceId")]
    return f"/aws/lambda/{names[0]}" if names else None


def _teardown(ctx, stack: str, auto_bucket: str | None, manual_bucket: str | None,
             handler_log_group: str | None) -> None:
    """Delete every resource this check created and CONFIRM each is gone.

    Inline rather than `ctx.on_cleanup`: a CloudFormation stack delete plus its confirming read
    does not reliably fit in the registered-cleanup cap.
    """
    found = sys.exc_info()[1]
    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    problems: list[str] = []

    def _lookup_handler_log_group() -> None:
        nonlocal handler_log_group
        handler_log_group = handler_log_group or _handler_log_group_from_stack(ctx, stack)

    def _reap_handler_log_group() -> None:
        if handler_log_group:
            _reap_log_group(ctx, handler_log_group,
                            budget_s=max(30.0, deadline - time.monotonic()))

    steps: list[tuple[str, Any]] = [
        (f"handler lookup on stack {stack}", _lookup_handler_log_group),
        (f"auto bucket {auto_bucket}",
         lambda: _delete_bucket_if_present(ctx.client("s3"), auto_bucket)),
        (f"manual bucket {manual_bucket}",
         lambda: _delete_bucket_if_present(ctx.client("s3"), manual_bucket)),
        (f"stack {stack}",
         lambda: _delete_stack_and_wait(ctx, stack,
                                        timeout_s=max(30.0, deadline - time.monotonic()))),
        ("handler log group", _reap_handler_log_group),
    ]
    for label, fn in steps:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 — teardown reports, never masks the verdict
            problems.append(f"{label}: {exc!r}")
    if problems:
        raise AssertionError(
            (f"{found!r}; " if found else "") + "teardown left residue: " + "; ".join(problems)
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
