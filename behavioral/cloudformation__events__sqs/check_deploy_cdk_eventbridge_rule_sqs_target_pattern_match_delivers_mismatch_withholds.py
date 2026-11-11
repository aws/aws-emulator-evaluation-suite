"""deploy-cdk-eventbridge-rule-sqs-target-pattern-match-delivers-mismatch-withholds."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "deploy-cdk-eventbridge-rule-sqs-target-pattern-match-delivers-mismatch-withholds"
GROUP = "deploy"
SERVICES = ["cloudformation", "events", "sqs"]

_APP = Path(__file__).parent / "deployments" / "cdk_rule_sqs_target"

_BOOTSTRAP_TIMEOUT_S = 300.0
_DEPLOY_TIMEOUT_S = 600.0
_DESTROY_TIMEOUT_S = 600.0

_SOURCE = "sim2real.cdkrulesqs"
_DETAIL_TYPE = "sim2real.watched"


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:deploy", "concern:eventing",
      "concern:e2e", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A plain CDK deploy of an EventBridge Rule targeting an SqsQueue delivers a matching
    `PutEvents` entry and withholds one whose detail-type does not match the rule's pattern.

    Reference: https://docs.aws.amazon.com/cdk/api/v2/docs/aws-cdk-lib.aws_events_targets.SqsQueue.html
    """
    ctx.verify_account_safety()
    require_tools("cdk", "node")
    assert (_APP / "app.py").is_file() and (_APP / "cdk.json").is_file(), (
        f"the CDK app this check deploys and destroys is missing from disk: expected app.py and "
        f"cdk.json under {_APP}, found "
        f"{sorted(p.name for p in _APP.iterdir()) if _APP.is_dir() else 'no such dir'}"
    )

    acct = ctx.account
    cfn = ctx.client("cloudformation")
    events = ctx.client("events")
    sqs = ctx.client("sqs")

    qualifier = ctx.unique_name("q")[:10]
    toolkit = ctx.unique_name("sim2real-cdktk-")
    stack = ctx.unique_name("sim2real-cdkrulesqs-")
    staging = f"cdk-{qualifier}-assets-{acct}-{ctx.region}"
    work = _stage(ctx, _APP)

    ctx.on_cleanup(lambda: _final_sweep(ctx, staging, toolkit, qualifier, stack))

    _bootstrap(ctx, qualifier, toolkit)
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack))

    _cdk(ctx, work, ["deploy", "--require-approval", "never", "--outputs-file", "out.json"],
         qualifier, stack, timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)

    outputs = json.loads((work / "out.json").read_text())[stack]
    rule_name = outputs["RuleName"]
    queue_url = outputs["QueueUrl"]
    queue_arn = outputs["QueueArn"]

    template = json.loads(
        (work / "cdk.out" / f"{stack}.template.json").read_text())["Resources"]
    assert "CDKMetadata" in template, (
        f"the synthesized template for {stack!r} carries no CDKMetadata resource; this check's "
        f"plain deploy must keep it"
    )
    type_counts = _type_counts(r["Type"] for r in template.values())
    for want_type in ("AWS::Events::Rule", "AWS::SQS::Queue", "AWS::SQS::QueuePolicy"):
        assert type_counts.get(want_type) == 1, (
            f"the synthesized template has {type_counts.get(want_type, 0)} {want_type} "
            f"resource(s), expected exactly 1; types seen: {type_counts!r}"
        )

    deployed = {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack)["StackResources"]
    }
    assert rule_name in deployed.values(), (
        f"the deployed stack's physical resource ids {sorted(deployed.values())!r} do not "
        f"include the rule output {rule_name!r}"
    )

    # ---- probe each resource through its own API before exercising anything -------------------
    rule = events.describe_rule(Name=rule_name)
    assert rule["Name"] == rule_name
    pattern = json.loads(rule["EventPattern"])
    assert pattern == {"source": [_SOURCE], "detail-type": [_DETAIL_TYPE]}, (
        f"DescribeRule on {rule_name!r} returned pattern {pattern!r}, expected the source and "
        f"detail-type the app declared"
    )
    rule_targets = events.list_targets_by_rule(Rule=rule_name)["Targets"]
    assert any(t["Arn"] == queue_arn for t in rule_targets), (
        f"ListTargetsByRule on {rule_name!r} returned {rule_targets!r}, expected one target "
        f"pointing at the queue arn {queue_arn!r}"
    )
    queue_attrs = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn", "Policy"]
    )["Attributes"]
    assert queue_attrs["QueueArn"] == queue_arn
    # CDK writes the target queue a policy admitting EventBridge, scoped to this exact rule.
    statements = json.loads(queue_attrs["Policy"])["Statement"]
    scoped = [
        st for st in statements
        if st.get("Effect") == "Allow"
        and st.get("Principal") == {"Service": "events.amazonaws.com"}
        and "sqs:SendMessage" in _as_list(st.get("Action"))
        and st.get("Resource") == queue_arn
        and st.get("Condition", {}).get("ArnEquals", {}).get("aws:SourceArn") == rule["Arn"]
    ]
    assert len(scoped) == 1, (
        f"the queue policy CDK wrote for {queue_url!r} has no SendMessage statement scoped to "
        f"rule {rule['Arn']!r}: {statements!r}"
    )

    # ---- positive control: a matching PutEvents entry arrives --------------------------------
    marker = ctx.unique_name("marker-match-")
    latency_s, matching_body = _put_and_wait(events, sqs, queue_url, marker, matching=True)
    assert matching_body["marker"] == marker, (
        f"the delivered detail's marker is {matching_body.get('marker')!r}, expected {marker!r}"
    )

    # ---- negative: a non-matching detail-type is never delivered ------------------------------
    other_marker = ctx.unique_name("marker-nomatch-")
    events.put_events(Entries=[{
        "Source": _SOURCE,
        "DetailType": "sim2real.unwatched",
        "Detail": json.dumps({"marker": other_marker}),
    }])
    seen_while_filtered = _absent_for(lambda: _receive(sqs, queue_url), latency_s)
    filtered_markers = [json.loads(m["Body"])["detail"]["marker"] for m in seen_while_filtered]
    assert other_marker not in filtered_markers, (
        f"marker {other_marker!r}, sent with a non-matching detail-type, reached the queue "
        f"{queue_url!r}; markers seen during the window: {filtered_markers!r}"
    )

    # ---- close the loop: the matching pattern still delivers on the same rule -----------------
    marker2 = ctx.unique_name("marker-match-two-")
    _, matching_body2 = _put_and_wait(events, sqs, queue_url, marker2, matching=True)
    assert matching_body2["marker"] == marker2, (
        f"a second matching PutEvents entry was not delivered; delivered marker "
        f"{matching_body2.get('marker')!r}, expected {marker2!r}"
    )

    # ---- cdk destroy, then every resource is verified gone through its own API -----------------
    _cdk(ctx, work, ["destroy", "--force"], qualifier, stack,
         timeout_s=_DESTROY_TIMEOUT_S, expect_rc=0)

    final = _error(lambda: cfn.describe_stacks(StackName=stack))
    assert final == ("ValidationError", f"Stack with id {stack} does not exist"), (
        f"after `cdk destroy --force`, DescribeStacks on {stack!r} raised {final!r}"
    )
    rule_gone = _error(lambda: events.describe_rule(Name=rule_name))
    assert rule_gone == (
        "ResourceNotFoundException",
        f"Rule {rule_name} does not exist on EventBus default.",
    ), (
        f"DescribeRule on the destroyed rule {rule_name!r} raised {rule_gone!r}"
    )
    queue_gone = _error(lambda: sqs.get_queue_url(QueueName=queue_url.rsplit("/", 1)[-1]))
    assert queue_gone == (
        "AWS.SimpleQueueService.NonExistentQueue",
        "The specified queue does not exist.",
    ), (
        f"GetQueueUrl on the destroyed queue {queue_url!r} raised {queue_gone!r}"
    )


def _put_and_wait(events, sqs, queue_url: str, marker: str, *, matching: bool,
                  timeout_s: float = 90.0) -> tuple[float, dict[str, Any]]:
    """PutEvents with a matching entry and poll until its marker arrives; ``(latency_s, detail)``.

    Re-sends on each poll so rule or target-policy propagation that is not yet effective self
    heals, matching how a real producer would retry.
    """
    assert matching, "this helper only sends matching entries; use put_events directly otherwise"
    start = time.monotonic()
    deadline = start + timeout_s
    seen: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        events.put_events(Entries=[{
            "Source": _SOURCE,
            "DetailType": _DETAIL_TYPE,
            "Detail": json.dumps({"marker": marker}),
        }])
        for message in sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        ).get("Messages", []):
            detail = json.loads(message["Body"])["detail"]
            seen.append(detail)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"])
        for detail in seen:
            if detail.get("marker") == marker:
                return time.monotonic() - start, detail
    raise AssertionError(f"{marker!r} never reached the queue in {timeout_s}s; saw {seen!r}")


def _receive(sqs, queue_url: str) -> list[dict[str, Any]]:
    """One bounded receive, deleting whatever it returns so a later poll cannot re-see it."""
    messages = sqs.receive_message(
        QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=1
    ).get("Messages", [])
    for message in messages:
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"])
    return messages


def _absent_for(observe, latency_s: float, *, factor: float = 3.0, floor_s: float = 10.0,
                poll_s: float = 2.0) -> list:
    """Everything ``observe()`` returned over ``max(floor_s, factor * latency_s)`` seconds."""
    window = max(floor_s, factor * latency_s)
    deadline = time.monotonic() + window
    seen: list = []
    while True:
        seen.extend(observe())
        if time.monotonic() >= deadline:
            return seen
        time.sleep(poll_s)


def _type_counts(types) -> dict[str, int]:
    counts: dict[str, int] = {}
    for t in types:
        counts[t] = counts.get(t, 0) + 1
    return counts


def _error(fn) -> tuple[str, str]:
    """The AWS (error code, message) a call raises; raises AssertionError if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return str(err["Code"]), str(err["Message"])
    raise AssertionError("call succeeded but was expected to be refused")


def _stage(ctx, app_dir: Path) -> Path:
    """Copy the CDK app to a temp workdir so cdk.out and out.json are not written beside it."""
    work = Path(tempfile.mkdtemp(prefix="sim2real-cdkrulesqs-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    shutil.copytree(app_dir, work, dirs_exist_ok=True)
    return work


def _bootstrap(ctx, qualifier: str, toolkit: str) -> None:
    ctx.verify_account_safety()
    acct = ctx.account
    boot = Path(tempfile.mkdtemp(prefix="sim2real-cdkboot-"))
    ctx.on_cleanup(lambda: shutil.rmtree(boot, ignore_errors=True))
    r = subprocess.run(
        ["cdk", "bootstrap", f"aws://{acct}/{ctx.region}", "--qualifier", qualifier,
         "--toolkit-stack-name", toolkit,
         "--bootstrap-kms-key-id", "AWS_MANAGED_KEY", "--ci"],
        cwd=boot, env=ctx.subprocess_env(), capture_output=True, text=True,
        timeout=_BOOTSTRAP_TIMEOUT_S)
    assert r.returncode == 0, (
        f"cdk bootstrap failed rc={r.returncode}: {(r.stdout + r.stderr)[-800:]!r}"
    )


def _cdk(ctx, work: Path, args: list[str], qualifier: str, stack: str, *, timeout_s: float,
         expect_rc: int | None) -> tuple[int, str]:
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    env["CDK_DEFAULT_REGION"] = ctx.region
    env["CDK_DEFAULT_ACCOUNT"] = ctx.account
    env["Q"] = qualifier
    env["STACK_NAME"] = stack
    env["CHECK_ID"] = CHECK
    # No --no-version-reporting: a plain deploy keeps AWS::CDK::Metadata in the template.
    cmd = ["cdk", *args, "--ci", "--no-notices", "--app", f"{sys.executable} app.py"]
    r = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True, timeout=timeout_s)
    rc, out = r.returncode, r.stdout + r.stderr
    if expect_rc is not None:
        assert rc == expect_rc, f"`cdk {args[0]}` rc={rc}, expected {expect_rc}: {out[-1200:]!r}"
    return rc, out


def _delete_stack_and_wait(ctx, stack: str, timeout_s: float = 540.0) -> None:
    """Delete by StackId, then poll to DELETE_COMPLETE; raises on DELETE_FAILED or timeout."""
    cfn = ctx.client("cloudformation")
    try:
        stack_id = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {stack} does not exist":
            return
        raise
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    status = "never read"
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            break
        time.sleep(2.0)
    raise AssertionError(
        f"stack {stack!r} is {status!r} after DeleteStack, expected DELETE_COMPLETE"
    )


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            objs = [{"Key": o["Key"], "VersionId": o["VersionId"]}
                    for o in page.get("Versions", []) + page.get("DeleteMarkers", [])]
            if objs:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "404"):
            raise


def _final_sweep(ctx, staging: str, toolkit: str, qualifier: str, stack: str) -> None:
    """Delete the bootstrap staging bucket and toolkit stack once the app stack is gone."""
    try:
        status = ctx.client("cloudformation").describe_stacks(
            StackName=stack)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Message"] != f"Stack with id {stack} does not exist":
            raise
        status = "DELETE_COMPLETE"
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"app stack {stack} is {status!r}: toolkit stack {toolkit} and "
                             f"staging bucket kept so the app stack can still be deleted")
    errors: list[str] = []
    for label, fn in (
        (f"staging bucket {staging}", lambda: _empty_and_delete_bucket(ctx, staging)),
        (f"toolkit stack {toolkit}", lambda: _delete_stack_and_wait(ctx, toolkit)),
    ):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - collected and raised below, every step still runs
            errors.append(f"{label}: {exc!r}")
    iam = ctx.client("iam")
    roles = [r["RoleName"] for page in iam.get_paginator("list_roles").paginate()
             for r in page["Roles"] if r["RoleName"].startswith(f"cdk-{qualifier}-")]
    if roles:
        errors.append(f"bootstrap roles {roles!r}")
    if errors:
        raise AssertionError(f"teardown left resources behind: {errors!r}")



def _as_list(value) -> list:
    """A policy's Action value as a list, whether written as one entry or several."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
