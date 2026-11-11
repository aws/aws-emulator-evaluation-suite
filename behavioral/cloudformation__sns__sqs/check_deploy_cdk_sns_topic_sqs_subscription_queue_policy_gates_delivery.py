"""deploy-cdk-sns-topic-sqs-subscription-queue-policy-gates-delivery."""
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

CHECK = "deploy-cdk-sns-topic-sqs-subscription-queue-policy-gates-delivery"
GROUP = "deploy"
SERVICES = ["cloudformation", "sns", "sqs"]

_APP = Path(__file__).parent / "deployments" / "cdk_sns_sqs_subscription"

_BOOTSTRAP_TIMEOUT_S = 300.0
_DEPLOY_TIMEOUT_S = 600.0
_DESTROY_TIMEOUT_S = 600.0
# SetQueueAttributes: a changed attribute can take up to 60 seconds to propagate.
_POLICY_PROPAGATION_S = 60.0


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:deploy", "concern:eventing",
      "concern:e2e", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A plain CDK deploy of an SNS Topic with an SqsSubscription delivers a published message
    inside the default envelope; clearing the queue policy CDK wrote withholds delivery until the
    same policy is restored, and `cdk destroy` removes the topic and the queue.

    Reference: https://docs.aws.amazon.com/cdk/api/v2/docs/aws-cdk-lib.aws_sns_subscriptions.SqsSubscription.html
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
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")

    qualifier = ctx.unique_name("q")[:10]
    toolkit = ctx.unique_name("sim2real-cdktk-")
    stack = ctx.unique_name("sim2real-cdksnssqs-")
    staging = f"cdk-{qualifier}-assets-{acct}-{ctx.region}"
    work = _stage(ctx, _APP)

    ctx.on_cleanup(lambda: _final_sweep(ctx, staging, toolkit, qualifier, stack))

    _bootstrap(ctx, qualifier, toolkit)
    # Failure-path net only: the asserted teardown is `cdk destroy` in the body below.
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack))

    _cdk(ctx, work, ["deploy", "--require-approval", "never", "--outputs-file", "out.json"],
         qualifier, stack, timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)

    outputs = json.loads((work / "out.json").read_text())[stack]
    topic_arn = outputs["TopicArn"]
    queue_url = outputs["QueueUrl"]
    queue_arn = outputs["QueueArn"]

    template = json.loads(
        (work / "cdk.out" / f"{stack}.template.json").read_text())["Resources"]
    assert "CDKMetadata" in template, (
        f"the synthesized template for {stack!r} carries no CDKMetadata resource; this check's "
        f"plain deploy must keep it"
    )
    type_counts = _type_counts(r["Type"] for r in template.values())
    for want_type in ("AWS::SNS::Topic", "AWS::SQS::Queue", "AWS::SQS::QueuePolicy",
                      "AWS::SNS::Subscription"):
        assert type_counts.get(want_type) == 1, (
            f"the synthesized template has {type_counts.get(want_type, 0)} {want_type} "
            f"resource(s), expected exactly 1; types seen: {type_counts!r}"
        )

    deployed = {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack)["StackResources"]
    }
    assert topic_arn in deployed.values(), (
        f"the deployed stack's physical resource ids {sorted(deployed.values())!r} do not "
        f"include the topic output {topic_arn!r}"
    )

    # ---- probe each resource through its own API before exercising anything -------------------
    topic_attrs = sns.get_topic_attributes(TopicArn=topic_arn)["Attributes"]
    assert topic_attrs["TopicArn"] == topic_arn, (
        f"GetTopicAttributes on {topic_arn!r} returned TopicArn {topic_attrs['TopicArn']!r}"
    )
    queue_attrs = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn", "Policy"]
    )["Attributes"]
    assert queue_attrs["QueueArn"] == queue_arn, (
        f"GetQueueAttributes on {queue_url!r} returned QueueArn {queue_attrs['QueueArn']!r}, "
        f"expected {queue_arn!r}"
    )
    original_policy = queue_attrs.get("Policy", "")
    # CDK writes the subscribed queue a policy admitting SNS, scoped to this exact topic.
    statements = json.loads(original_policy)["Statement"]
    scoped = [
        st for st in statements
        if st.get("Effect") == "Allow"
        and st.get("Principal") == {"Service": "sns.amazonaws.com"}
        and st.get("Action") == "sqs:SendMessage"
        and st.get("Resource") == queue_arn
        and st.get("Condition", {}).get("ArnEquals", {}).get("aws:SourceArn") == topic_arn
    ]
    assert len(scoped) == 1, (
        f"the queue policy CDK wrote for {queue_url!r} has no SendMessage statement scoped to "
        f"topic {topic_arn!r}: {statements!r}"
    )
    subs = sns.list_subscriptions_by_topic(TopicArn=topic_arn)["Subscriptions"]
    assert [(x["Protocol"], x["Endpoint"]) for x in subs] == [("sqs", queue_arn)], (
        f"ListSubscriptionsByTopic on {topic_arn!r} returned {subs!r}, expected the one queue"
    )

    # ---- positive control #1: a published message arrives, wrapped in the SNS envelope --------
    marker1 = ctx.unique_name("marker-one-")
    latency_s, envelope1 = _publish_and_wait(sns, sqs, topic_arn, queue_url, marker1)
    assert envelope1["TopicArn"] == topic_arn, (
        f"the delivered envelope's TopicArn is {envelope1['TopicArn']!r}, expected {topic_arn!r}"
    )
    assert envelope1["Message"] == marker1, (
        f"the delivered envelope's Message is {envelope1['Message']!r}, expected {marker1!r}"
    )

    # ---- break exactly one thing: replace CDK's queue policy with an owner-only policy ---------
    restrictive_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "OwnerOnly",
            "Effect": "Allow",
            "Principal": {"AWS": acct},
            "Action": "sqs:*",
            "Resource": queue_arn,
        }],
    })
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": restrictive_policy})
    reread = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["Policy"])["Attributes"]
    assert "sns.amazonaws.com" not in reread.get("Policy", ""), (
        f"the replacement policy on {queue_url!r} still grants sns.amazonaws.com: "
        f"{reread.get('Policy')!r}"
    )

    # Until the change propagates a probe may still arrive; the first probe that stays absent
    # for the whole contrast window is the graded one, and every probe arriving fails.
    marker2, blocked_bodies = _blocked_probe(ctx, sns, sqs, topic_arn, queue_url, latency_s)
    assert marker2 not in blocked_bodies, (
        f"marker {marker2!r} reached the queue {queue_url!r} after its sending permission was "
        f"revoked; messages seen during the blocked window: {blocked_bodies!r}"
    )

    # ---- restore the exact policy CDK wrote and close the loop ---------------------------------
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": original_policy})
    marker3 = ctx.unique_name("marker-three-")
    _, envelope3 = _publish_and_wait(sns, sqs, topic_arn, queue_url, marker3,
                                     timeout_s=_POLICY_PROPAGATION_S + 90.0)
    assert envelope3["Message"] == marker3, (
        f"after restoring the queue policy, the delivered envelope's Message is "
        f"{envelope3['Message']!r}, expected {marker3!r} — delivery did not resume"
    )

    # ---- cdk destroy, then every resource is verified gone through its own API -----------------
    _cdk(ctx, work, ["destroy", "--force"], qualifier, stack,
         timeout_s=_DESTROY_TIMEOUT_S, expect_rc=0)

    final = _error(lambda: cfn.describe_stacks(StackName=stack))
    assert final == ("ValidationError", f"Stack with id {stack} does not exist"), (
        f"after `cdk destroy --force`, DescribeStacks on {stack!r} raised {final!r}"
    )

    topic_gone = _error(lambda: sns.get_topic_attributes(TopicArn=topic_arn))
    assert topic_gone == ("NotFound", "Topic does not exist"), (
        f"GetTopicAttributes on the destroyed topic {topic_arn!r} raised {topic_gone!r}, "
        f"expected ('NotFound', 'Topic does not exist')"
    )
    queue_gone = _error(lambda: sqs.get_queue_url(QueueName=queue_url.rsplit("/", 1)[-1]))
    assert queue_gone == (
        "AWS.SimpleQueueService.NonExistentQueue",
        "The specified queue does not exist.",
    ), (
        f"GetQueueUrl on the destroyed queue {queue_url!r} raised {queue_gone!r}"
    )


def _publish_and_wait(sns, sqs, topic_arn: str, queue_url: str, marker: str,
                      *, timeout_s: float = 90.0) -> tuple[float, dict[str, Any]]:
    """Publish ``marker`` and poll until it arrives; returns ``(latency_s, envelope)``.

    Re-publishes on each poll so a subscription or queue policy that is not yet effective self
    heals, matching how a real client would retry.
    """
    start = time.monotonic()
    deadline = start + timeout_s
    seen: list[str] = []
    while time.monotonic() < deadline:
        sns.publish(TopicArn=topic_arn, Message=marker)
        for message in sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        ).get("Messages", []):
            body = json.loads(message["Body"])
            seen.append(body)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"])
        for body in seen:
            if body.get("Message") == marker:
                return time.monotonic() - start, body
    raise AssertionError(f"{marker!r} never reached the queue in {timeout_s}s; saw {seen!r}")


def _blocked_probe(ctx, sns, sqs, topic_arn: str, queue_url: str,
                   latency_s: float) -> tuple[str, list[str]]:
    """Publish fresh probes until one is absent for ``max(10 s, 3 x latency_s)``; return it and
    the bodies seen in its window. Raises if probes still arrive once the change has propagated."""
    deadline = time.monotonic() + _POLICY_PROPAGATION_S
    while True:
        probe = ctx.unique_name("marker-two-")
        published_at = time.monotonic()
        sns.publish(TopicArn=topic_arn, Message=probe)
        bodies = [json.loads(m["Body"])["Message"]
                  for m in _absent_for(lambda: _receive(sqs, queue_url), latency_s)]
        if probe not in bodies or published_at >= deadline:
            return probe, bodies


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
    work = Path(tempfile.mkdtemp(prefix="sim2real-cdksnssqs-"))
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
