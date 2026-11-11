"""cdk-deploy-kms-alias-encrypted-queue-names-the-key-and-round-trips-a-message-then-destroyed."""
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

CHECK = "cdk-deploy-kms-alias-encrypted-queue-names-the-key-and-round-trips-a-message-then-destroyed"
GROUP = "deploy"
SERVICES = ["cloudformation", "kms", "sqs"]

_BOOTSTRAP_TIMEOUT_S = 300.0
_DEPLOY_TIMEOUT_S = 300.0
_TEARDOWN_DEADLINE_S = 300.0
# ---------------------------------------------------------------------------------------------

_APP = Path(__file__).parent / "deployments" / "cdk-kms-sqs"


@tags(
    "axis:happy-path", "cap:c1", "concern:data-plane", "concern:deploy",
    "concern:representation", "dp:api", "plane:data",
)
def run(ctx) -> None:
    """A CDK-deployed KMS Key with an Alias, used as an SQS queue's server-side encryption key:
    GetQueueAttributes names the key by its own ARN and a sent message round-trips; a plain
    `cdk destroy` then removes the queue outright and schedules the key for deletion.
    """
    from fidelity_tests_runner import require_tools

    require_tools("cdk", "node")
    ctx.verify_account_safety()

    assert (_APP / "app.py").is_file() and (_APP / "cdk.json").is_file(), (
        f"the CDK app this check deploys is missing from disk: expected app.py and cdk.json under "
        f"{_APP}, found {sorted(p.name for p in _APP.iterdir()) if _APP.is_dir() else 'no such dir'}"
    )

    kms = ctx.client("kms")
    sqs = ctx.client("sqs")
    acct = ctx.client("sts").get_caller_identity()["Account"]

    qualifier = ctx.unique_name("q")[:10]
    toolkit = ctx.unique_name("sim2real-cdktk-")
    stack = ctx.unique_name("sim2real-xsvc-kmssqs-")
    staging = f"cdk-{qualifier}-assets-{acct}-{ctx.region}"
    key_alias = ctx.unique_name("sim2real-xsvc-kmssqs-alias-")

    work = _stage(ctx, _APP)
    state: dict[str, Any] = {"key_id": None, "queue_url": None}
    ctx.on_cleanup(lambda: _teardown(ctx, stack, staging, toolkit, qualifier, state))

    _bootstrap(ctx, qualifier, toolkit)
    _cdk(ctx, work, ["deploy", "--require-approval", "never", "--outputs-file", "out.json"],
         qualifier, stack, acct, key_alias, timeout_s=_DEPLOY_TIMEOUT_S, expect_rc=0)

    outputs = json.loads((work / "out.json").read_text())[stack]
    key_id = outputs["KeyId"]
    alias_name = outputs["AliasName"]
    queue_url = outputs["QueueUrl"]
    state["key_id"] = key_id
    state["queue_url"] = queue_url

    assert alias_name == f"alias/{key_alias}", (
        f"the stack's AliasName output is {alias_name!r}, expected 'alias/{key_alias}'"
    )

    # ---- 1. the key exists and the alias resolves to it -----------------------------------
    key_desc = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert key_desc["KeyState"] == "Enabled", (
        f"the deployed key {key_id!r} is in state {key_desc['KeyState']!r}, expected 'Enabled'"
    )
    alias_desc = kms.describe_key(KeyId=alias_name)["KeyMetadata"]
    assert alias_desc["KeyId"] == key_id, (
        f"DescribeKey({alias_name!r}) resolves to key {alias_desc['KeyId']!r}, expected the "
        f"deployed key {key_id!r}"
    )

    # ---- 2. THE HEADLINE: the queue names the key, and a message round-trips --------------
    attrs = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["KmsMasterKeyId"])["Attributes"]
    assert attrs.get("KmsMasterKeyId") == key_desc["Arn"], (
        f"GetQueueAttributes reports KmsMasterKeyId={attrs.get('KmsMasterKeyId')!r}, expected the "
        f"deployed key's own ARN {key_desc['Arn']!r}"
    )

    body = f"sim2real-payload-{stack}"
    sqs.send_message(QueueUrl=queue_url, MessageBody=body)
    received = _receive_one(sqs, queue_url, timeout_s=30.0)
    assert received["Body"] == body, (
        f"the KMS-encrypted queue returned body {received['Body']!r}, expected the sent {body!r}"
    )
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=received["ReceiptHandle"])

    # ---- 3. cdk destroy, in-band, is the graded teardown -----------------------------------
    _cdk(ctx, work, ["destroy", "--force"], qualifier, stack, acct, key_alias,
         timeout_s=_TEARDOWN_DEADLINE_S, expect_rc=0)

    # ---- 4. every resource is gone through its own API -------------------------------------
    queue_code, queue_message = _error(
        lambda: sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["All"]))
    assert (queue_code, queue_message) == (
        "AWS.SimpleQueueService.NonExistentQueue", "The specified queue does not exist."), (
        f"after cdk destroy, GetQueueAttributes({queue_url!r}) returned {queue_code!r}: "
        f"{queue_message!r}, expected an outright not-found"
    )
    final_state = kms.describe_key(KeyId=key_id)["KeyMetadata"]["KeyState"]
    assert final_state == "PendingDeletion", (
        f"after cdk destroy, key {key_id!r} is in state {final_state!r}; AWS never deletes a KMS "
        f"key outright, so 'PendingDeletion' is the correct 'gone' signal for it"
    )
    alias_arn = f"arn:aws:kms:{ctx.region}:{acct}:{alias_name}"
    alias_code, alias_message = _error(lambda: kms.describe_key(KeyId=alias_name))
    assert (alias_code, alias_message) == (
        "NotFoundException", f"Alias {alias_arn} is not found."), (
        f"after cdk destroy, DescribeKey({alias_name!r}) returned {alias_code!r}: "
        f"{alias_message!r}, expected an outright not-found - the alias itself must be gone even "
        f"though the key it pointed to only enters PendingDeletion"
    )


def _stage(ctx, app_dir: Path) -> Path:
    """Copy the on-disk CDK app to a temp workdir so cdk.out / cdk.context.json / out.json are
    never written next to the check."""
    work = Path(tempfile.mkdtemp(prefix="sim2real-cdkkmssqs-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    shutil.copytree(app_dir, work, dirs_exist_ok=True)
    return work


def _error(fn):
    """The captured AWS (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _receive_one(sqs, queue_url: str, *, timeout_s: float) -> dict[str, Any]:
    """Long-poll for exactly one message, raising if none arrives in time."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=1,
            WaitTimeSeconds=min(10, max(1, int(deadline - time.monotonic()))),
        )
        messages = resp.get("Messages", [])
        if messages:
            return messages[0]
    raise AssertionError(f"no message arrived on {queue_url!r} within {timeout_s}s")


def _bootstrap(ctx, qualifier: str, toolkit: str) -> None:
    from fidelity_tests_runner import require_tools

    require_tools("cdk", "node")
    ctx.verify_account_safety()
    acct = ctx.client("sts").get_caller_identity()["Account"]
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


def _cdk(ctx, work: Path, args: list[str], qualifier: str, stack: str, acct: str,
         key_alias: str, *, timeout_s: float, expect_rc: int | None) -> tuple[int, str]:
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    env["CDK_DEFAULT_REGION"] = ctx.region
    env["CDK_DEFAULT_ACCOUNT"] = acct
    env["Q"] = qualifier
    env["STACK_NAME"] = stack
    env["CHECK_ID"] = CHECK
    env["KEY_ALIAS"] = key_alias
    cmd = ["cdk", *args, "--ci", "--no-version-reporting", "--no-notices",
           "--app", f"{sys.executable} app.py"]
    r = subprocess.run(cmd, cwd=work, env=env, capture_output=True, text=True, timeout=timeout_s)
    rc, out = r.returncode, r.stdout + r.stderr
    if expect_rc is not None:
        assert rc == expect_rc, f"`cdk {args[0]}` rc={rc}, expected {expect_rc}: {out[-1200:]!r}"
    return rc, out


def _delete_stack_and_wait(ctx, stack: str, timeout_s: float = 240.0) -> None:
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
        time.sleep(5.0)
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


def _teardown(ctx, stack: str, staging: str, toolkit: str, qualifier: str,
              state: dict[str, Any]) -> None:
    """Safety net for the in-band `cdk destroy` above: idempotent against a run that already
    destroyed everything, and raises naming whatever is still present otherwise."""
    errors: list[str] = []
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    ssm = ctx.client("ssm")

    for label, fn in (
        (f"app stack {stack}", lambda: _delete_stack_and_wait(ctx, stack)),
        (f"staging bucket {staging}", lambda: _empty_and_delete_bucket(ctx, staging)),
        (f"toolkit stack {toolkit}", lambda: _delete_stack_and_wait(ctx, toolkit)),
    ):
        if errors:
            raise AssertionError(f"toolkit stack {toolkit} and staging bucket {staging} kept: "
                                  + "; ".join(errors))
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - collected and raised below, every step still runs
            errors.append(f"{label}: {exc!r}")

    deadline = time.monotonic() + _TEARDOWN_DEADLINE_S
    remaining: list[str] = ["teardown verification never ran"]
    while time.monotonic() < deadline:
        remaining = []
        try:
            st = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
            if st != "DELETE_COMPLETE":
                remaining.append(f"app stack {st}")
        except ClientError as exc:
            if exc.response["Error"]["Message"] != f"Stack with id {stack} does not exist":
                raise
        try:
            st = cfn.describe_stacks(StackName=toolkit)["Stacks"][0]["StackStatus"]
            if st != "DELETE_COMPLETE":
                remaining.append(f"toolkit stack {st}")
        except ClientError as exc:
            if exc.response["Error"]["Message"] != f"Stack with id {toolkit} does not exist":
                raise
        try:
            s3.head_bucket(Bucket=staging)
            remaining.append(f"staging bucket {staging} still present")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "404":
                raise
        try:
            ssm.get_parameter(Name=f"/cdk-bootstrap/{qualifier}/version")
            remaining.append("bootstrap version parameter still present")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ParameterNotFound":
                raise
        if state.get("queue_url"):
            try:
                ctx.client("sqs").get_queue_attributes(
                    QueueUrl=state["queue_url"], AttributeNames=["QueueArn"])
                remaining.append(f"queue {state['queue_url']} still present")
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "AWS.SimpleQueueService.NonExistentQueue":
                    raise
        if not remaining:
            break
        time.sleep(10.0)
    else:
        errors.append(f"remnants still present after {_TEARDOWN_DEADLINE_S}s: {remaining!r}")

    if state.get("key_id") and not errors:
        kms = ctx.client("kms")
        kstate = kms.describe_key(KeyId=state["key_id"])["KeyMetadata"]["KeyState"]
        if kstate != "PendingDeletion":
            try:
                kms.schedule_key_deletion(KeyId=state["key_id"], PendingWindowInDays=7)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "KMSInvalidStateException":
                    raise
    if errors:
        raise AssertionError(f"teardown failed to converge: {errors!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
