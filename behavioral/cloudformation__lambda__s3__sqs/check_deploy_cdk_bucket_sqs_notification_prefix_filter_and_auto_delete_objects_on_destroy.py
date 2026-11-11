"""deploy-cdk-bucket-sqs-notification-prefix-filter-and-auto-delete-objects-on-destroy."""
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

CHECK = "deploy-cdk-bucket-sqs-notification-prefix-filter-and-auto-delete-objects-on-destroy"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda", "s3", "sqs"]

_APP = Path(__file__).parent / "deployments" / "cdk_bucket_notification_autodelete"

_BOOTSTRAP_TIMEOUT_S = 300.0
_DEPLOY_TIMEOUT_S = 600.0
_DESTROY_TIMEOUT_S = 600.0
_TEARDOWN_DEADLINE_S = 420.0

_WATCHED_PREFIX = "watched/"
_IGNORED_PREFIX = "ignored/"


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:deploy", "concern:eventing",
      "concern:e2e", "concern:data-plane", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A plain CDK deploy of an auto-delete Bucket with a prefixed SQS notification delivers for
    a matching key and withholds for a non-matching one; `cdk destroy` still empties and removes
    the bucket though it holds objects, because `auto_delete_objects` empties it first.

    Reference: https://docs.aws.amazon.com/cdk/api/v2/docs/aws-cdk-lib.aws_s3.Bucket.html#aws_cdk.aws_s3.Bucket.add_event_notification
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
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")

    qualifier = ctx.unique_name("q")[:10]
    toolkit = ctx.unique_name("sim2real-cdktk-")
    stack = ctx.unique_name("sim2real-cdks3notif-")
    staging = f"cdk-{qualifier}-assets-{acct}-{ctx.region}"
    work = _stage(ctx, _APP)
    handler_log_groups: list[str] = []

    ctx.on_cleanup(lambda: _final_sweep(ctx, staging, toolkit, qualifier, stack,
                                        handler_log_groups))

    _bootstrap(ctx, qualifier, toolkit)
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack))

    _cdk(ctx, work, ["deploy", "--require-approval", "never", "--outputs-file", "out.json"],
         qualifier, stack, timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)

    outputs = json.loads((work / "out.json").read_text())[stack]
    bucket_name = outputs["BucketName"]
    queue_url = outputs["QueueUrl"]
    queue_arn = outputs["QueueArn"]

    template = json.loads(
        (work / "cdk.out" / f"{stack}.template.json").read_text())["Resources"]
    assert "CDKMetadata" in template, (
        f"the synthesized template for {stack!r} carries no CDKMetadata resource; this check's "
        f"plain deploy must keep it"
    )
    type_counts = _type_counts(r["Type"] for r in template.values())
    for want_type in ("AWS::S3::Bucket", "AWS::SQS::Queue", "AWS::SQS::QueuePolicy",
                      "Custom::S3AutoDeleteObjects", "Custom::S3BucketNotifications"):
        assert type_counts.get(want_type) == 1, (
            f"the synthesized template has {type_counts.get(want_type, 0)} {want_type} "
            f"resource(s), expected exactly 1; types seen: {type_counts!r}"
        )

    deployed = {
        r["LogicalResourceId"]: r
        for r in cfn.describe_stack_resources(StackName=stack)["StackResources"]
    }
    assert bucket_name in {r["PhysicalResourceId"] for r in deployed.values()}, (
        f"the deployed stack's physical resource ids do not include the bucket output "
        f"{bucket_name!r}"
    )
    handler_log_groups.extend(
        f"/aws/lambda/{r['PhysicalResourceId']}" for r in deployed.values()
        if r["ResourceType"] == "AWS::Lambda::Function"
    )
    assert len(handler_log_groups) == 2, (
        f"the deployed stack has {len(handler_log_groups)} Lambda function(s) "
        f"({handler_log_groups!r}), expected exactly 2 (the notifications and auto-delete "
        f"handlers)"
    )

    # ---- probe each resource through its own API before exercising anything -------------------
    s3.head_bucket(Bucket=bucket_name)
    queue_attrs = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn", "Policy"]
    )["Attributes"]
    assert queue_attrs["QueueArn"] == queue_arn
    # CDK writes the notified queue a policy admitting S3, scoped to this exact bucket.
    bucket_arn = f"arn:aws:s3:::{bucket_name}"
    statements = json.loads(queue_attrs["Policy"])["Statement"]
    scoped = [
        st for st in statements
        if st.get("Effect") == "Allow"
        and st.get("Principal") == {"Service": "s3.amazonaws.com"}
        and "sqs:SendMessage" in _as_list(st.get("Action"))
        and st.get("Resource") == queue_arn
        and bucket_arn in _condition_arns(st.get("Condition", {}))
    ]
    assert len(scoped) == 1, (
        f"the queue policy CDK wrote for {queue_url!r} has no SendMessage statement scoped to "
        f"bucket {bucket_arn!r}: {statements!r}"
    )
    notif = s3.get_bucket_notification_configuration(Bucket=bucket_name)
    queue_configs = notif.get("QueueConfigurations", [])
    assert len(queue_configs) == 1, (
        f"GetBucketNotificationConfiguration on {bucket_name!r} returned "
        f"{len(queue_configs)} queue configuration(s), expected exactly 1: {queue_configs!r}"
    )
    qc = queue_configs[0]
    assert qc["QueueArn"] == queue_arn, (
        f"the bucket's notification QueueArn is {qc['QueueArn']!r}, expected {queue_arn!r}"
    )
    assert "s3:ObjectCreated:*" in qc["Events"], (
        f"the bucket's notification Events are {qc['Events']!r}, expected 's3:ObjectCreated:*'"
    )
    filter_rules = qc["Filter"]["Key"]["FilterRules"]
    assert any(
        r["Name"].lower() == "prefix" and r["Value"] == _WATCHED_PREFIX for r in filter_rules
    ), (
        f"the bucket's notification filter rules are {filter_rules!r}, expected a prefix rule "
        f"on {_WATCHED_PREFIX!r}"
    )

    # ---- positive control: a matching key's PutObject produces the notification ---------------
    marker1 = ctx.unique_name("marker-watched-one-")
    key1 = f"{_WATCHED_PREFIX}{marker1}"
    latency_s, record1 = _put_and_wait(s3, sqs, bucket_name, key1, queue_url)
    assert record1["s3"]["bucket"]["name"] == bucket_name, (
        f"the delivered record's bucket name is {record1['s3']['bucket']['name']!r}, expected "
        f"{bucket_name!r}"
    )
    assert record1["eventName"].startswith("ObjectCreated:"), (
        f"the delivered record's eventName is {record1['eventName']!r}, expected it to start "
        f"with 'ObjectCreated:'"
    )

    # ---- negative: a key outside the prefix filter is never delivered -------------------------
    marker2 = ctx.unique_name("marker-ignored-")
    key2 = f"{_IGNORED_PREFIX}{marker2}"
    s3.put_object(Bucket=bucket_name, Key=key2, Body=marker2.encode())
    seen_while_filtered = _absent_for(lambda: _receive(sqs, queue_url), latency_s)
    filtered_keys = [
        rec["s3"]["object"]["key"]
        for m in seen_while_filtered
        for rec in json.loads(m["Body"]).get("Records", [])
    ]
    assert key2 not in filtered_keys, (
        f"key {key2!r}, outside the notification's prefix filter, reached the queue "
        f"{queue_url!r}; keys seen during the window: {filtered_keys!r}"
    )

    # ---- close the loop: a second matching key still delivers ----------------------------------
    marker3 = ctx.unique_name("marker-watched-two-")
    key3 = f"{_WATCHED_PREFIX}{marker3}"
    _, record3 = _put_and_wait(s3, sqs, bucket_name, key3, queue_url)
    assert record3["s3"]["object"]["key"] == key3, (
        f"a second matching PutObject was not delivered; delivered key "
        f"{record3['s3']['object']['key']!r}, expected {key3!r}"
    )

    # ---- the bucket holds every object just written, so the destroy below is of a non-empty
    # ---- bucket; auto_delete_objects is what makes it succeed anyway ---------------------------
    listing = s3.list_objects_v2(Bucket=bucket_name)
    assert sorted(o["Key"] for o in listing.get("Contents", [])) == sorted([key1, key2, key3]), (
        f"before the destroy, bucket {bucket_name!r} lists "
        f"{sorted(o['Key'] for o in listing.get('Contents', []))!r}, expected the three keys "
        f"this check wrote"
    )

    handler_functions = sorted(
        r["PhysicalResourceId"] for r in deployed.values() if r["ResourceType"] == "AWS::Lambda::Function"
    )
    roles = _stack_roles(cfn, stack)

    # ---- cdk destroy, then every resource is verified gone through its own API -----------------
    _cdk(ctx, work, ["destroy", "--force"], qualifier, stack,
         timeout_s=_DESTROY_TIMEOUT_S, expect_rc=0)

    final = _error(lambda: cfn.describe_stacks(StackName=stack))
    assert final == ("ValidationError", f"Stack with id {stack} does not exist"), (
        f"after `cdk destroy --force`, DescribeStacks on {stack!r} raised {final!r}"
    )
    bucket_gone = _error(lambda: s3.head_bucket(Bucket=bucket_name))
    assert bucket_gone[0] == "404", (
        f"HeadBucket on the destroyed bucket {bucket_name!r} raised {bucket_gone!r}, expected "
        f"code '404'"
    )
    queue_gone = _error(lambda: sqs.get_queue_url(QueueName=queue_url.rsplit("/", 1)[-1]))
    assert queue_gone == (
        "AWS.SimpleQueueService.NonExistentQueue",
        "The specified queue does not exist.",
    ), (
        f"GetQueueUrl on the destroyed queue {queue_url!r} raised {queue_gone!r}"
    )

    lam = ctx.client("lambda")
    for name in handler_functions:
        arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{name}"
        got = _error(lambda name=name: lam.get_function(FunctionName=name))
        assert got == ("ResourceNotFoundException", f"Function not found: {arn}"), (
            f"the custom-resource handler {name!r} after the destroy: {got!r}"
        )
    _assert_roles_gone(ctx.client("iam"), roles)


def _put_and_wait(s3, sqs, bucket: str, key: str, queue_url: str,
                  *, timeout_s: float = 90.0) -> tuple[float, dict[str, Any]]:
    """PutObject at ``key`` and poll until its notification record arrives: ``(latency_s, record)``."""
    start = time.monotonic()
    s3.put_object(Bucket=bucket, Key=key, Body=key.encode())
    deadline = start + timeout_s
    seen: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        for message in sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        ).get("Messages", []):
            for record in json.loads(message["Body"]).get("Records", []):
                seen.append(record)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"])
        for record in seen:
            if record["s3"]["object"]["key"] == key:
                return time.monotonic() - start, record
    raise AssertionError(
        f"PutObject at {key!r} never produced a notification in {timeout_s}s; saw "
        f"{[r['s3']['object']['key'] for r in seen]!r}"
    )


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
    work = Path(tempfile.mkdtemp(prefix="sim2real-cdks3notif-"))
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


def _reap_log_group(ctx, name: str, *, reads: int = 3, interval_s: float = 2.0,
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


def _final_sweep(ctx, staging: str, toolkit: str, qualifier: str, stack: str,
                 handler_log_groups: list[str]) -> None:
    """Delete the bootstrap staging bucket, toolkit stack and handler log groups once the app
    stack is gone."""
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
    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    errors: list[str] = []
    for label, fn in (
        (f"staging bucket {staging}", lambda: _empty_and_delete_bucket(ctx, staging)),
        (f"toolkit stack {toolkit}", lambda: _delete_stack_and_wait(ctx, toolkit)),
        *(
            (f"handler log group {name}",
             lambda name=name: _reap_log_group(
                 ctx, name, budget_s=max(30.0, deadline - time.monotonic())))
            for name in handler_log_groups
        ),
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


def _condition_arns(condition: dict) -> list[str]:
    """Every ``aws:SourceArn`` value across whichever condition operator the policy used."""
    values: list[str] = []
    for operands in condition.values():
        value = operands.get("aws:SourceArn")
        if value is None:
            continue
        values += value if isinstance(value, list) else [value]
    return values

def _stack_roles(cfn, stack: str) -> list[str]:
    """Names of every AWS::IAM::Role the stack created, read before its delete."""
    resources = cfn.describe_stack_resources(StackName=stack)["StackResources"]
    return sorted(r["PhysicalResourceId"] for r in resources if r["ResourceType"] == "AWS::IAM::Role")


def _assert_roles_gone(iam, roles: list[str]) -> None:
    """Each role answers NoSuchEntity with IAM's exact message."""
    for role in roles:
        try:
            iam.get_role(RoleName=role)
        except ClientError as exc:
            got = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
            assert got == ("NoSuchEntity", f"The role with name {role} cannot be found."), (
                f"GetRole({role!r}) after the stack delete: {got!r}"
            )
            continue
        raise AssertionError(f"role {role!r} survived the stack delete")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
