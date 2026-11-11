"""cdk-deploy-sns-lambda-subscription-notification."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

from behavioral_harness import tags

CHECK = "cdk-deploy-sns-lambda-subscription-notification"
GROUP = "deployment-order"
SERVICES = ["events", "lambda", "sns"]

_APP_DIR = Path(__file__).parent / "deployments" / "sns_lambda_cdk"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CDK stack wiring an SNS subscription to a Lambda function delivers published
    notifications to the function after deployment."""
    sqs = ctx.client("sqs")
    queue_name = _xname(ctx, "sink")
    queue_url = sqs.create_queue(QueueName=queue_name, tags=_xsvc_resource_tags())["QueueUrl"]
    ctx.on_cleanup(_tolerant(lambda: sqs.delete_queue(QueueUrl=queue_url), *_SQS_NF))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    stack = _deploy_cdk(
        ctx,
        _APP_DIR,
        context={
            "include_permission": "true",
            "queue_url": queue_url,
            "queue_arn": queue_arn,
        },
    )

    sns = ctx.client("sns")
    marker = ctx.unique_name("marker-")
    sns.publish(TopicArn=stack["outputs"]["TopicArn"], Message=marker)

    bodies = _collect_messages(sqs, queue_url, timeout_s=90, marker=marker)
    assert any(marker in b for b in bodies), "function was never invoked by the sns subscription"
    lambda_event = json.loads(next(b for b in bodies if marker in b))
    record = lambda_event["Records"][0]
    assert record["EventSource"] == "aws:sns", f"expected aws:sns event source, got {record.get('EventSource')!r}"
    assert record["Sns"]["Message"] == marker, f"expected message {marker!r}, got {record['Sns'].get('Message')!r}"
    assert record["Sns"]["TopicArn"] == stack["outputs"]["TopicArn"], (
        f"expected TopicArn {stack['outputs']['TopicArn']!r}, got {record['Sns'].get('TopicArn')!r}"
    )

    # Destroy the stack, then prove it and every resource it provisioned gone.
    cfn = ctx.client("cloudformation")
    physical: dict[str, list[str]] = {}
    for r in _paged(cfn, "list_stack_resources", "StackResourceSummaries", StackName=stack["stack_id"]):
        physical.setdefault(r["ResourceType"], []).append(r["PhysicalResourceId"])
    for rtype in ("AWS::SNS::Topic", "AWS::SNS::Subscription", "AWS::Lambda::Function", "AWS::IAM::Role"):
        assert len(physical.get(rtype, [])) == 1, (
            f"expected the stack to provision exactly one {rtype}, got {physical.get(rtype, [])!r}"
        )
    _gone_stack(ctx, stack["stack_name"], stack["stack_id"])
    _absent_subscription(ctx, physical["AWS::SNS::Subscription"][0])
    _absent_topic(ctx, physical["AWS::SNS::Topic"][0])
    _absent_lambda(ctx, physical["AWS::Lambda::Function"][0])
    _absent_role(ctx, physical["AWS::IAM::Role"][0])
    _gone_queue(ctx, queue_name, queue_url)


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
            if "does not exist" not in exc.response["Error"].get("Message", ""):
                raise
            return "GONE"

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
    require_tools("cdk", "node")
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
    env["CDK_DEFAULT_ACCOUNT"] = ctx.account

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


#: A valid template for the UpdateStack-on-a-deleted-stack beat: with a template body the refusal is
#: the not-found ValidationError ``Stack [<name>] does not exist`` (a missing template is refused
#: for that reason first on some targets).
_GONE_TEMPLATE = '{"Resources": {"Gone": {"Type": "AWS::CloudFormation::WaitConditionHandle"}}}'

#: Bounded convergence for a delete to reach its terminal not-found answer (the default service
#: class budget); a deadline, never an assertion on elapsed time.
_GONE_S = 120.0


def _err(exc: ClientError) -> tuple[str, int, str]:
    """(code, HTTP status, message) of a ClientError."""
    e = exc.response.get("Error", {})
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    return e.get("Code") or "", status, e.get("Message") or e.get("message") or ""


def _refused(fn, codes: tuple[str, ...], status: int, what: str) -> None:
    """``fn()`` must fail with one of ``codes`` in the HTTP class of ``status``, a non-empty message."""
    try:
        fn()
    except ClientError as exc:
        code, got, msg = _err(exc)
        in_class = isinstance(got, int) and got // 100 == status // 100
        assert code in codes and in_class, (
            f"{what}: expected {'/'.join(codes)} HTTP {status // 100}xx, got {code!r} HTTP {got!r}: {msg[:150]!r}"
        )
        assert msg.strip(), f"{what}: {code} carries an empty message"
        return
    raise AssertionError(f"{what}: expected {'/'.join(codes)} HTTP {status}, the call succeeded")


def _poll_refused(fn, codes, status, what, timeout_s: float = _GONE_S) -> None:
    """Poll ``fn`` until it reaches the terminal not-found answer, then grade it with ``_refused``.

    A success while the delete converges is retried; any other error fails at once.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            code, _, _ = _err(exc)
            if code in codes:
                _refused(fn, codes, status, what)
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what}: still readable {timeout_s:.0f}s after the delete")
        time.sleep(1.0)


def _tolerant(fn, *codes: str):
    """A teardown that ignores only the given not-found codes (the body already deleted it)."""

    def run() -> None:
        try:
            fn()
        except ClientError as exc:
            if _err(exc)[0] not in codes:
                raise

    return run


def _paged(client, op: str, key: str, **kw) -> list:
    """Every element of ``key`` across all pages of ``op``."""
    out: list = []
    for page in client.get_paginator(op).paginate(**kw):
        out.extend(page.get(key, []))
    return out


_SQS_NF = ("AWS.SimpleQueueService.NonExistentQueue", "QueueDoesNotExist")


def _gone_stack(ctx, name: str, stack_id: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + _GONE_S
    while True:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            break
        assert status in ("DELETE_IN_PROGRESS",) or status.endswith("_COMPLETE"), f"stack delete reached {status}"
        assert time.monotonic() < deadline, f"stack still {status} {_GONE_S:.0f}s after DeleteStack"
        time.sleep(2.0)
    active = [s for s in _paged(cfn, "list_stacks", "StackSummaries") if s["StackName"] == name and s["StackStatus"] != "DELETE_COMPLETE"]
    assert not active, f"ListStacks still lists {name} as {active[0]['StackStatus']}"
    _refused(lambda: cfn.update_stack(StackName=name, TemplateBody=_GONE_TEMPLATE), ("ValidationError",), 400, f"UpdateStack {name}")


def _absent_subscription(ctx, sub_arn: str) -> None:
    sns = ctx.client("sns")
    nf = ("NotFound",)
    _poll_refused(lambda: sns.get_subscription_attributes(SubscriptionArn=sub_arn), nf, 404, "GetSubscriptionAttributes")
    listed = {s["SubscriptionArn"] for s in _paged(sns, "list_subscriptions", "Subscriptions")}
    assert sub_arn not in listed, "ListSubscriptions still lists the stack's deleted subscription"
    _refused(
        lambda: sns.set_subscription_attributes(SubscriptionArn=sub_arn, AttributeName="RawMessageDelivery", AttributeValue="true"),
        nf, 404, "SetSubscriptionAttributes on deleted subscription",
    )


def _absent_lambda(ctx, name: str) -> None:
    lam = ctx.client("lambda")
    nf = ("ResourceNotFoundException",)
    _poll_refused(lambda: lam.get_function(FunctionName=name), nf, 404, f"GetFunction {name}")
    listed = {f["FunctionName"] for f in _paged(lam, "list_functions", "Functions")}
    assert name not in listed, f"ListFunctions still lists the stack's deleted function {name}"
    _refused(lambda: lam.invoke(FunctionName=name, Payload=b"{}"), nf, 404, f"Invoke {name}")


def _absent_role(ctx, name: str) -> None:
    iam = ctx.client("iam")
    nf = ("NoSuchEntity",)
    _poll_refused(lambda: iam.get_role(RoleName=name), nf, 404, f"GetRole {name}")
    listed = {r["RoleName"] for r in _paged(iam, "list_roles", "Roles")}
    assert name not in listed, f"ListRoles still lists the stack's deleted role {name}"
    doc = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:GetQueueUrl","Resource":"*"}]}'
    _refused(
        lambda: iam.put_role_policy(RoleName=name, PolicyName="gone", PolicyDocument=doc),
        nf, 404, f"PutRolePolicy {name}",
    )


def _absent_topic(ctx, arn: str) -> None:
    sns = ctx.client("sns")
    nf = ("NotFound",)
    _poll_refused(lambda: sns.get_topic_attributes(TopicArn=arn), nf, 404, "GetTopicAttributes")
    listed = {t["TopicArn"] for t in _paged(sns, "list_topics", "Topics")}
    assert arn not in listed, "ListTopics still lists the stack's deleted topic"
    _refused(lambda: sns.publish(TopicArn=arn, Message="gone"), nf, 404, "Publish to deleted topic")


def _gone_queue(ctx, name: str, url: str) -> None:
    sqs = ctx.client("sqs")
    sqs.delete_queue(QueueUrl=url)
    # AWS documents up to 60 s for a deleted queue to stop answering.
    _poll_refused(lambda: sqs.get_queue_url(QueueName=name), _SQS_NF, 400, f"GetQueueUrl {name}")
    listed = sqs.list_queues(QueueNamePrefix=name).get("QueueUrls", [])
    assert not [u for u in listed if u.rstrip("/").split("/")[-1] == name], (
        f"ListQueues still lists deleted queue {name}"
    )
    _refused(lambda: sqs.send_message(QueueUrl=url, MessageBody="gone"), _SQS_NF, 400, f"SendMessage {name}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
