"""cdk-s3-public-access-blocked-by-default-flag-governs-whether-a-public-bucket-policy-is-rejected."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cdk-s3-public-access-blocked-by-default-flag-governs-whether-a-public-bucket-policy-is-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3"]

_DEPLOY_TIMEOUT_S = 300.0
_SYNTH_TIMEOUT_S = 180.0
_DESTROY_TIMEOUT_S = 300.0
_TEARDOWN_DEADLINE_S = 300.0

_APP = "cdk_s3_public_access_block_flag"
_FLAG = "@aws-cdk/aws-s3:publicAccessBlockedByDefault"

_POLICY_SID = "PublicReadGetObject"


def _public_read_policy(bucket: str) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": _POLICY_SID,
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket}/*",
        }],
    }


@tags("axis:rejection", "cap:c7", "concern:deploy", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx) -> None:
    """With `publicAccessBlockedByDefault` unset, a bucket declaring only `blockPublicAcls` keeps
    BlockPublicPolicy false; with it set, every option is filled in true and S3 rejects a public
    bucket policy. Both arms are read back through GetPublicAccessBlock; no bucket is made public.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    account = ctx.client("sts").get_caller_identity()["Account"]
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]
    s3 = ctx.client("s3")

    stack_off = ctx.unique_name("sim2real-cdkpaboff-")
    stack_on = ctx.unique_name("sim2real-cdkpabon-")
    base_off = {"account": account, "region": ctx.region, "stack_name": stack_off}
    base_on = {"account": account, "region": ctx.region, "stack_name": stack_on}
    flag_on_ctx = {**base_on, _FLAG: "true"}

    work = _stage_app(ctx, _APP)
    state: dict[str, Any] = {"destroyed_off": False, "destroyed_on": False}

    def _cleanup() -> None:
        stacks = []
        if not state["destroyed_off"]:
            stacks.append(stack_off)
        if not state["destroyed_on"]:
            stacks.append(stack_on)
        _teardown(ctx, stacks)

    ctx.on_cleanup(_cleanup)

    # ---- 1. one context value, two templates, from the same source file ----------------------
    _, _, template_off = _synth_doc(ctx, work, stack_off, base_off, out="out-off",
                                    timeout_s=_SYNTH_TIMEOUT_S)
    _, _, template_on = _synth_doc(ctx, work, stack_on, flag_on_ctx, out="out-on",
                                   timeout_s=_SYNTH_TIMEOUT_S)
    pab_off = _public_access_block_property(template_off)
    pab_on = _public_access_block_property(template_on)
    assert pab_off == {"BlockPublicAcls": True}, (
        f"with {_FLAG} unset the template's PublicAccessBlockConfiguration is {pab_off!r}, "
        f"expected only {{'BlockPublicAcls': True}} — the three unset options must stay absent"
    )
    assert pab_on == {
        "BlockPublicAcls": True, "BlockPublicPolicy": True,
        "IgnorePublicAcls": True, "RestrictPublicBuckets": True,
    }, (
        f"with {_FLAG}=true the template's PublicAccessBlockConfiguration is {pab_on!r}, expected "
        f"every option filled in true"
    )

    # ---- 2. deploy the UNSET arm: S3 defaults the unsent options, BlockPublicPolicy included,
    # to false. No public policy is put on this bucket: the setting alone is the observable.
    _cdk(ctx, work, ["deploy", stack_off, "--require-approval", "never"], base_off,
         timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)
    bucket_off = _stack_outputs(ctx, stack_off)["BucketName"]
    config_off = s3.get_public_access_block(Bucket=bucket_off)["PublicAccessBlockConfiguration"]
    assert config_off == {
        "BlockPublicAcls": True, "IgnorePublicAcls": False,
        "BlockPublicPolicy": False, "RestrictPublicBuckets": False,
    }, (
        f"GetPublicAccessBlock on the unset-flag bucket returned {config_off!r}, expected only "
        f"BlockPublicAcls true and the rest false"
    )

    # ---- 3. deploy the FLAG-ON arm: BlockPublicPolicy true makes S3 refuse a public policy ---
    _cdk(ctx, work, ["deploy", stack_on, "--require-approval", "never"], flag_on_ctx,
         timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)
    bucket_on = _stack_outputs(ctx, stack_on)["BucketName"]
    config_on = s3.get_public_access_block(Bucket=bucket_on)["PublicAccessBlockConfiguration"]
    assert config_on == {
        "BlockPublicAcls": True, "IgnorePublicAcls": True,
        "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
    }, (
        f"GetPublicAccessBlock on the flag-enabled bucket returned {config_on!r}, expected every "
        f"option true"
    )

    exc = _client_error(
        lambda: s3.put_bucket_policy(Bucket=bucket_on,
                                     Policy=json.dumps(_public_read_policy(bucket_on)))
    )
    assert exc.response["Error"]["Code"] == "AccessDenied", (
        f"PutBucketPolicy with a public statement on the flag-enabled bucket raised "
        f"{exc.response['Error']['Code']!r}, expected 'AccessDenied'"
    )
    expected_message = (
        f"User: {caller_arn} is not authorized to perform: s3:PutBucketPolicy on resource: "
        f'"arn:aws:s3:::{bucket_on}" because public policies are prevented by the '
        f"BlockPublicPolicy setting in S3 Block Public Access."
    )
    assert exc.response["Error"]["Message"] == expected_message, exc.response["Error"]["Message"]

    # Effect absent: the rejected PutBucketPolicy never landed.
    gone = _client_error(lambda: s3.get_bucket_policy(Bucket=bucket_on))
    assert gone.response["Error"]["Code"] == "NoSuchBucketPolicy", (
        f"GetBucketPolicy on {bucket_on!r} raised {gone.response['Error']['Code']!r}, expected "
        f"'NoSuchBucketPolicy' — the rejected PutBucketPolicy must not have applied anything"
    )

    # ---- teardown, asserted -----------------------------------------------------------------
    _cdk(ctx, work, ["destroy", stack_off, "--force"], base_off,
         timeout_s=_DESTROY_TIMEOUT_S, expect_rc=0)
    state["destroyed_off"] = True
    _assert_stack_absent(ctx, stack_off)

    _cdk(ctx, work, ["destroy", stack_on, "--force"], flag_on_ctx,
         timeout_s=_DESTROY_TIMEOUT_S, expect_rc=0)
    state["destroyed_on"] = True
    _assert_stack_absent(ctx, stack_on)


# ===== self-contained helpers =====


def _public_access_block_property(template: dict[str, Any]) -> dict[str, Any]:
    for resource in template["Resources"].values():
        if resource["Type"] == "AWS::S3::Bucket":
            return resource["Properties"].get("PublicAccessBlockConfiguration", {})
    raise AssertionError(f"no AWS::S3::Bucket resource in template; resources were "
                         f"{sorted(template['Resources'])!r}")


def _teardown(ctx, stacks: list[str], after: list[tuple[str, Any]] | None = None) -> None:
    """Delete each stack this run created, then run each after step; raise every failure."""
    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    problems: list[str] = []
    steps = [
        (f"stack {stack}", lambda s=stack: _delete_stack_and_wait(
            ctx, s, timeout_s=max(30.0, deadline - time.monotonic())))
        for stack in stacks
    ]
    steps += list(after or [])
    for label, fn in steps:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - every step runs; the failures are raised below
            problems.append(f"{label}: {exc!r}")
    if problems:
        raise AssertionError(f"teardown left problems behind: {problems!r}")


def _delete_stack_and_wait(ctx, stack: str, *, timeout_s: float = 300.0) -> None:
    cfn = ctx.client("cloudformation")
    try:
        stack_id = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {stack} does not exist":
            return
        raise
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    last = "never read"
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if last == "DELETE_COMPLETE":
            return
        if last == "DELETE_FAILED":
            raise AssertionError(f"stack {stack!r} reached DELETE_FAILED during teardown")
        time.sleep(5.0)
    raise AssertionError(
        f"stack {stack!r} did not reach DELETE_COMPLETE within {timeout_s}s (last status {last!r})"
    )


def _stage_app(ctx, name: str) -> Path:
    """Copy `deployments/<name>` into a temp dir so `cdk.out` never lands in the repo."""
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
    ctx.verify_account_safety()
    cmd = ["cdk", *args, "--ci", "--no-notices", "--no-version-reporting", "--no-color"]
    for key, value in context.items():
        cmd += ["--context", f"{key}={value}"]
    result = subprocess.run(cmd, cwd=work, env=ctx.subprocess_env(), capture_output=True,
                            text=True, timeout=timeout_s)
    output = result.stdout + result.stderr
    if expect_rc is not None:
        assert result.returncode == expect_rc, (
            f"`cdk {' '.join(args)}` exited {result.returncode}, expected {expect_rc}; output "
            f"tail: {output[-1200:]!r}"
        )
    return result.returncode, output


def _synth_doc(ctx, work: Path, stack: str, context: dict[str, str], *, out: str,
               timeout_s: float) -> tuple[int, str, dict[str, Any]]:
    """Synthesise into `<work>/<out>`, asserting exit 0; return `(rc, output, parsed template)`."""
    shutil.rmtree(work / out, ignore_errors=True)
    rc, output = _cdk(ctx, work, ["synth", stack, "--output", out, "--quiet"], context,
                      timeout_s=timeout_s, expect_rc=0)
    template = work / out / f"{stack}.template.json"
    assert template.is_file(), (
        f"`cdk synth` exited {rc} but wrote no template at {template}; {out} contains "
        f"{sorted(p.name for p in (work / out).iterdir()) if (work / out).is_dir() else 'nothing'}"
    )
    return rc, output, json.loads(template.read_text())


def _stack_outputs(ctx, stack: str) -> dict[str, str]:
    """The deployed stack's Outputs, read from CloudFormation rather than the CLI's own record."""
    described = ctx.client("cloudformation").describe_stacks(StackName=stack)["Stacks"][0]
    assert described["StackStatus"] == "CREATE_COMPLETE", (
        f"stack {stack!r} is {described['StackStatus']!r}, expected CREATE_COMPLETE before "
        f"reading its outputs"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
