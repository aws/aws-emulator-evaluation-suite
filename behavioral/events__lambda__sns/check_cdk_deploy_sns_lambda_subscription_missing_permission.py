"""cdk-deploy-sns-lambda-subscription-missing-permission."""
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

CHECK = "cdk-deploy-sns-lambda-subscription-missing-permission"
GROUP = "permission-boundary"
SERVICES = ["events", "lambda", "sns"]

_APP_DIR = Path(__file__).parent / "deployments" / "sns_lambda_cdk"


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CDK stack that omits the Lambda permission for the SNS subscription principal never
    invokes the function; the same app WITH the permission (positive control) does."""
    require_tools("cdk")
    sqs = ctx.client("sqs")
    sns = ctx.client("sns")

    # --- broken: CfnSubscription with no matching lambda:InvokeFunction permission ---
    broken_queue_url = sqs.create_queue(
        QueueName=_xname(ctx, "sink-broken"), tags=_xsvc_resource_tags()
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=broken_queue_url))
    broken_queue_arn = sqs.get_queue_attributes(
        QueueUrl=broken_queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    broken = _deploy_cdk(
        ctx,
        _APP_DIR,
        context={
            "include_permission": "false",
            "queue_url": broken_queue_url,
            "queue_arn": broken_queue_arn,
        },
    )
    marker_broken = ctx.unique_name("marker-broken-")
    sns.publish(TopicArn=broken["outputs"]["TopicArn"], Message=marker_broken)
    bodies = _collect_messages(sqs, broken_queue_url, timeout_s=40)
    assert not any(marker_broken in b for b in bodies), "function was invoked despite missing permission"

    # --- positive control: same app, permission included ---
    fixed_queue_url = sqs.create_queue(
        QueueName=_xname(ctx, "sink-fixed"), tags=_xsvc_resource_tags()
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=fixed_queue_url))
    fixed_queue_arn = sqs.get_queue_attributes(
        QueueUrl=fixed_queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    fixed = _deploy_cdk(
        ctx,
        _APP_DIR,
        context={
            "include_permission": "true",
            "queue_url": fixed_queue_url,
            "queue_arn": fixed_queue_arn,
        },
    )
    marker_fixed = ctx.unique_name("marker-fixed-")
    sns.publish(TopicArn=fixed["outputs"]["TopicArn"], Message=marker_fixed)
    bodies = _collect_messages(sqs, fixed_queue_url, timeout_s=90, marker=marker_fixed)
    assert any(marker_fixed in b for b in bodies), "positive control: function was never invoked"


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"
_CDK_BOOTSTRAP_PARAM = "BootstrapVersion"
_CDK_BOOTSTRAP_RULE = "CheckBootstrapVersion"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError") or (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" not in exc.response["Error"]["Message"]
            ):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _strip_cdk_bootstrap(template_json: str) -> str:
    doc = json.loads(template_json)
    params = doc.get("Parameters") or {}
    rules = doc.get("Rules") or {}
    params.pop(_CDK_BOOTSTRAP_PARAM, None)
    rules.pop(_CDK_BOOTSTRAP_RULE, None)
    for key, value in (("Parameters", params), ("Rules", rules)):
        if value:
            doc[key] = value
        else:
            doc.pop(key, None)
    rest = json.dumps(doc)
    for marker in ("/cdk-bootstrap/", "cdk-hnb659fds-assets"):
        if marker in rest:
            raise AssertionError(
                f"CDK app needs a bootstrapped environment ({marker} referenced) — it has file or "
                "image assets. Make the app asset-free (inline Lambda code as a string) so the "
                "synthesized template deploys through plain CloudFormation."
            )
    return rest


def _deploy_cdk(ctx, app_dir, *, stack=None, context=None, timeout_s=300.0) -> dict[str, Any]:
    ctx.verify_account_safety()

    src = Path(app_dir)
    work = Path(tempfile.mkdtemp(prefix="sim2real-xsvc-cdk-"))
    shutil.copytree(
        src,
        work,
        dirs_exist_ok=True,
        ignore=shutil.ignore_patterns("cdk.out", ".venv", "__pycache__", "node_modules"),
    )
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))

    env = ctx.subprocess_env()
    env["CDK_DEFAULT_REGION"] = ctx.region
    env["CDK_DEFAULT_ACCOUNT"] = ctx.client("sts").get_caller_identity()["Account"]

    asm = work / "cdk.out"
    cmd = [
        "cdk", "synth",
        "--output", str(asm),
        "--ci",
        "--no-version-reporting",
        "--no-asset-metadata",
        "--no-path-metadata",
    ]
    if stack:
        cmd.append(stack)
    for k, v in (context or {}).items():
        cmd.extend(["--context", f"{k}={v}"])
    synth = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True, timeout=180)
    if synth.returncode != 0:
        raise AssertionError(f"cdk synth failed: {synth.stderr[-500:]}")

    templates = sorted(asm.glob("*.template.json"))
    if stack:
        templates = [t for t in templates if t.name == f"{stack}.template.json"] or templates
    if not templates:
        raise AssertionError(f"cdk synth produced no template in {asm}")
    if len(templates) > 1:
        names = ", ".join(t.name[: -len(".template.json")] for t in templates)
        raise AssertionError(f"app synthesized {len(templates)} stacks ({names}) — pass stack=...")

    return _deploy_cfn(ctx, _strip_cdk_bootstrap(templates[0].read_text()), timeout_s=timeout_s)


def _collect_messages(sqs, queue_url, *, timeout_s, marker=None):
    deadline = time.monotonic() + timeout_s
    found: list[str] = []
    while time.monotonic() < deadline:
        remaining = max(1, min(10, int(deadline - time.monotonic())))
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=remaining)
        for msg in resp.get("Messages", []):
            found.append(msg["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        if marker and any(marker in b for b in found):
            return found
    return found


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
