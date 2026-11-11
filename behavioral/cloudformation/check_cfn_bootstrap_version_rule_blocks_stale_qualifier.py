"""cfn-bootstrap-version-rule-blocks-stale-qualifier."""
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

CHECK = "cfn-bootstrap-version-rule-blocks-stale-qualifier"
GROUP = "deploy"
SERVICES = ["cloudformation"]

_APP = "cdk_bootstrap_version_rule"
_BOOTSTRAP_TIMEOUT_S = 900.0
_CREATE_TIMEOUT_S = 300.0
_TEARDOWN_DEADLINE_S = 420.0


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A synthesized template's CheckBootstrapVersion Rule refuses CreateStack when this
    qualifier's bootstrap version is too low, with the Rule's own message and no resource
    created; restoring the version lets the identical template create and the table works.

    Reference: https://docs.aws.amazon.com/cdk/v2/guide/bootstrapping.html
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")

    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    ddb = ctx.client("dynamodb")

    qualifier = ctx.unique_name("q")[:10]
    toolkit_stack = ctx.unique_name("sim2real-cdktk-")
    stack_name = ctx.unique_name("sim2real-cfnrule-")
    param_name = f"/cdk-bootstrap/{qualifier}/version"

    work = _stage_app(ctx, _APP)
    template = _synth(ctx, work, stack_name, qualifier)

    assert_description, excluded = _bootstrap_rule(template)
    assert excluded, (
        f"synthesized template's CheckBootstrapVersion Rule excluded no versions: "
        f"{template.get('Rules')!r} — the template is not an asset under DefaultStackSynthesizer"
    )
    stale_version = max(excluded, key=int)

    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, toolkit_stack, _TEARDOWN_DEADLINE_S))
    staging_bucket = f"cdk-{qualifier}-assets-{ctx.account}-{ctx.region}"
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx.client("s3"), staging_bucket))
    _bootstrap(ctx, qualifier, toolkit_stack)

    real_version = ssm.get_parameter(Name=param_name)["Parameter"]["Value"]
    assert real_version not in excluded, (
        f"this run's own bootstrap wrote version {real_version!r} into the set the Rule "
        f"excludes {sorted(excluded, key=int)!r} — the negative arm below would prove nothing"
    )

    # 1. NEGATIVE: downgrade this qualifier's parameter below what the Rule requires, then submit
    #    the synthesized template directly. CloudFormation must refuse during CREATE, with the
    #    Rule's own exact assertion message, and leave nothing provisioned.
    ssm.put_parameter(Name=param_name, Value=stale_version, Type="String", Overwrite=True)
    template_body = json.dumps(template)
    created = cfn.create_stack(StackName=stack_name, TemplateBody=template_body)
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_name, _TEARDOWN_DEADLINE_S))
    assert created["StackId"], f"create_stack returned no StackId: {created!r}"

    status, reason = _wait_terminal(ctx, cfn, stack_name, _CREATE_TIMEOUT_S)
    assert status == "ROLLBACK_COMPLETE", (
        f"stack {stack_name!r} reached {status!r} with bootstrap version {stale_version!r} "
        f"against a Rule excluding {sorted(excluded, key=int)!r}; expected ROLLBACK_COMPLETE"
    )
    expected_reason = f"Parameter validation failed: assertion error: {assert_description}. " \
                       f"Rollback requested by user."
    assert reason == expected_reason, (
        f"rollback reason was {reason!r}, expected the Rule's own assertion message "
        f"{expected_reason!r}"
    )
    resources = cfn.list_stack_resources(StackName=stack_name)["StackResourceSummaries"]
    assert resources == [], (
        f"stack {stack_name!r} rolled back with {len(resources)} resource(s) still listed: "
        f"{resources!r} — a Rule failure during CREATE must provision nothing"
    )

    # 2. CONTROL: delete the empty, rolled-back stack, restore the real bootstrap version, and
    #    resubmit the IDENTICAL template under the SAME name. It must create and the table works.
    _delete_stack_and_wait(cfn, stack_name, _TEARDOWN_DEADLINE_S, ctx=ctx)
    ssm.put_parameter(Name=param_name, Value=real_version, Type="String", Overwrite=True)
    cfn.create_stack(StackName=stack_name, TemplateBody=template_body)

    status2, _ = _wait_terminal(ctx, cfn, stack_name, _CREATE_TIMEOUT_S)
    assert status2 == "CREATE_COMPLETE", (
        f"stack {stack_name!r} reached {status2!r} after restoring bootstrap version "
        f"{real_version!r}; expected CREATE_COMPLETE — the parameter was not the cause"
    )
    table_name = _stack_output(cfn, stack_name, "TableName")
    key = ctx.unique_name("key-")
    marker = ctx.unique_name("marker-")
    ddb.put_item(TableName=table_name, Item={"pk": {"S": key}, "marker": {"S": marker}})
    item = ddb.get_item(TableName=table_name, Key={"pk": {"S": key}},
                        ConsistentRead=True).get("Item")
    assert item is not None, (
        f"GetItem on {table_name!r} found nothing at pk={key!r} right after PutItem — "
        f"CREATE_COMPLETE was reached but the deployed table does not work"
    )
    assert item.get("marker", {}).get("S") == marker, (
        f"item at pk={key!r} carries marker {item.get('marker', {}).get('S')!r}, expected "
        f"{marker!r}"
    )


def _stage_app(ctx, name: str) -> Path:
    """Copy `deployments/<name>` into a temp dir so `cdk.out` never lands in the repo."""
    source = Path(__file__).parent / "deployments" / name
    assert source.is_dir(), (
        f"the CDK app this check references is missing from disk: {source} does not exist "
        f"(artifact defect, not a missing prerequisite)"
    )
    work = Path(tempfile.mkdtemp(prefix=f"sim2real-{name}-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    staged = work / name
    shutil.copytree(source, staged, ignore=shutil.ignore_patterns(
        "cdk.out", "out-*", ".venv", "__pycache__", "node_modules"))
    return staged


def _synth(ctx, work: Path, stack_name: str, qualifier: str) -> dict[str, Any]:
    """`cdk synth` the asset-free app under this run's qualifier; returns the template dict."""
    ctx.verify_account_safety()
    cmd = [
        "cdk", "synth", "--ci", "--no-version-reporting", "--no-notices", "--no-color",
        "--context", f"stack_name={stack_name}",
        "--context", f"qualifier={qualifier}",
        "--context", f"account={ctx.account}",
        "--context", f"region={ctx.region}",
    ]
    result = subprocess.run(cmd, cwd=work, env=ctx.subprocess_env(), capture_output=True,
                            text=True, timeout=180)
    assert result.returncode == 0, (
        f"`cdk synth` exited {result.returncode}, expected 0: "
        f"{(result.stdout + result.stderr)[-1200:]!r}"
    )
    template_path = work / "cdk.out" / f"{stack_name}.template.json"
    assert template_path.is_file(), f"synth did not produce {template_path}"
    return json.loads(template_path.read_text())


def _bootstrap_rule(template: dict[str, Any]) -> tuple[str, list[str]]:
    """The CheckBootstrapVersion Rule's own AssertDescription and its excluded version list."""
    rules = template.get("Rules", {})
    rule = rules.get("CheckBootstrapVersion")
    assert rule is not None, (
        f"synthesized template carries no CheckBootstrapVersion Rule: {sorted(rules)!r} — "
        f"DefaultStackSynthesizer did not make the template an asset"
    )
    assertion = rule["Assertions"][0]
    excluded = assertion["Assert"]["Fn::Not"][0]["Fn::Contains"][0]
    return assertion["AssertDescription"], excluded


def _bootstrap(ctx, qualifier: str, toolkit_stack: str) -> None:
    """`cdk bootstrap` for one per-run qualifier, in a scratch cwd with no app of its own."""
    ctx.verify_account_safety()
    scratch = Path(tempfile.mkdtemp(prefix="sim2real-cdkboot-"))
    ctx.on_cleanup(lambda: shutil.rmtree(scratch, ignore_errors=True))
    cmd = [
        "cdk", "bootstrap", f"aws://{ctx.account}/{ctx.region}",
        "--qualifier", qualifier,
        "--toolkit-stack-name", toolkit_stack,
        "--bootstrap-kms-key-id", "AWS_MANAGED_KEY",
        "--ci", "--no-version-reporting", "--no-notices", "--no-color",
        "--tags", f"sim2real={CHECK}",
    ]
    try:
        result = subprocess.run(cmd, cwd=scratch, env=ctx.subprocess_env(), capture_output=True,
                                text=True, timeout=_budget_s(ctx, _BOOTSTRAP_TIMEOUT_S))
    except subprocess.TimeoutExpired:
        if _budget_spent(ctx):
            raise TimeoutError(f"`cdk bootstrap` for qualifier {qualifier!r}: the run budget "
                               f"ended first; not graded") from None
        raise
    assert result.returncode == 0, (
        f"`cdk bootstrap` for qualifier {qualifier!r} exited {result.returncode}, expected 0: "
        f"{(result.stdout + result.stderr)[-1200:]!r}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_terminal(ctx, cfn, stack_name: str, timeout_s: float) -> tuple[str, str | None]:
    """Poll to a terminal stack status; returns (status, the stack-level event's reason)."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    status = "UNKNOWN"
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status.endswith("_COMPLETE") or status.endswith("_FAILED"):
            break
        time.sleep(3.0)
    else:
        if _budget_spent(ctx):
            raise TimeoutError(f"stack {stack_name!r} reaching a terminal status: the run budget "
                               f"ended first; not graded")
        raise AssertionError(f"stack {stack_name!r} did not reach a terminal status within "
                             f"{timeout_s}s (last status {status!r})")
    reason = None
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_name):
        for event in page["StackEvents"]:
            if event["LogicalResourceId"] == stack_name and \
                    event["ResourceStatus"] in ("ROLLBACK_IN_PROGRESS", "CREATE_FAILED"):
                reason = event.get("ResourceStatusReason")
                break
        if reason is not None:
            break
    return status, reason


def _stack_output(cfn, stack_name: str, key: str) -> str:
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    assert key in outputs, f"stack {stack_name!r} outputs {sorted(outputs)!r} do not include {key!r}"
    return outputs[key]


def _delete_stack_and_wait(cfn, stack_name: str, timeout_s: float, ctx=None) -> None:
    """Delete a stack and poll to DELETE_COMPLETE; a mid-run call passes ctx to cap the wait."""
    if ctx is not None:
        timeout_s = _budget_s(ctx, timeout_s)
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if "does not exist" in str(exc):
            return
        raise
    deadline = time.monotonic() + timeout_s
    last = "never read"
    while time.monotonic() < deadline:
        try:
            last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            error = exc.response.get("Error", {})
            if error.get("Code") == "ValidationError" and \
                    error.get("Message") == f"Stack with id {stack_name} does not exist":
                return
            raise
        if last == "DELETE_COMPLETE":
            return
        if last == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name!r} reached DELETE_FAILED during teardown")
        time.sleep(5.0)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"stack {stack_name!r} reaching DELETE_COMPLETE: the run budget ended "
                           f"first; not graded")
    raise AssertionError(
        f"stack {stack_name!r} did not reach DELETE_COMPLETE within {timeout_s}s (last {last!r})"
    )


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    """Purge every version and delete marker, then the bucket (StagingBucket has DeletionPolicy: Retain)."""
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objects = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objects:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objects})
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "404"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
