"""pipes-log-configuration-absent-by-default-and-cmk-key-identifier-echoed."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pipes-log-configuration-absent-by-default-and-cmk-key-identifier-echoed"

GROUP = "observability"

SERVICES = ["kms", "pipes", "sqs"]


@tags("axis:happy-path", "cap:c1",
      "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribePipe omits LogConfiguration for a pipe created without one (no implied default is
    reported), and reports the exact KMS key identifier for a pipe created with a CMK.
    """
    source = _create_queue(ctx)
    target = _create_queue(ctx)

    # --- No LogConfiguration at create: DescribePipe omits the field entirely. ---
    plain_role = _create_pipe_role(ctx, source["arn"], target["arn"])
    plain_pipe = _create_pipe(
        ctx,
        source=source["arn"],
        target=target["arn"],
        role_arn=plain_role["arn"],
        desired_state="STOPPED",
        wait_for="STOPPED",
    )
    described = ctx.client("pipes").describe_pipe(Name=plain_pipe)
    assert "LogConfiguration" not in described, (
        f"a pipe created with no LogConfiguration must omit the field on DescribePipe (no "
        f"implied default is reported), got {described.get('LogConfiguration')!r}"
    )

    # --- CMK: KmsKeyIdentifier set at create, echoed back exactly. ---
    kms = ctx.client("kms")
    key = kms.create_key(
        Description=_xname(ctx, "key"),
        Tags=[{"TagKey": "sim2real", "TagValue": "true"}],
    )["KeyMetadata"]
    key_arn = key["Arn"]
    key_id = key["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    cmk_role = _create_pipe_role(ctx, source["arn"], target["arn"])
    policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AccountRoot",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
                    "Action": "kms:*",
                    "Resource": "*",
                },
                {
                    "Sid": "PipeExecutionRole",
                    "Effect": "Allow",
                    "Principal": {"AWS": cmk_role["arn"]},
                    "Action": ["kms:DescribeKey", "kms:GenerateDataKey", "kms:Decrypt"],
                    "Resource": "*",
                },
            ],
        }
    )
    # A just-created role's ARN is not immediately a valid KMS policy principal (IAM
    # propagation); retry until it is.
    timeout_s = _budget_s(ctx, 60.0)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=policy)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "MalformedPolicyDocumentException":
                raise
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"KMS refused the new role as a key policy principal for {timeout_s:.0f}s: {exc}"
                ) from exc
            time.sleep(5)

    cmk_pipe = _create_pipe(
        ctx,
        source=source["arn"],
        target=target["arn"],
        role_arn=cmk_role["arn"],
        desired_state="STOPPED",
        wait_for="STOPPED",
        KmsKeyIdentifier=key_arn,
    )
    described = ctx.client("pipes").describe_pipe(Name=cmk_pipe)
    assert described.get("KmsKeyIdentifier") == key_arn, (
        f"a pipe created with KmsKeyIdentifier={key_arn!r} must echo it back exactly on "
        f"DescribePipe, got {described.get('KmsKeyIdentifier')!r}"
    )

    # Control: the plain pipe, which named no CMK, must not echo one.
    plain_described = ctx.client("pipes").describe_pipe(Name=plain_pipe)
    assert "KmsKeyIdentifier" not in plain_described, (
        f"a pipe created with no KmsKeyIdentifier must not echo one, got "
        f"{plain_described.get('KmsKeyIdentifier')!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _budget_s(ctx, cap_s):
    """A wait's timeout, bounded by the runner's remaining time so the wait fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - 5.0))


def _poll_until(probe, predicate, *, timeout_s, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise TimeoutError(f"{description} not met within {timeout_s:.0f}s. Last result: {last!r}")


def _teardown(undo, *not_found: str):
    """A cleanup running undo() where a failed delete raises; only not_found codes mean it's gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_queue(ctx, **attrs: str) -> dict[str, str]:
    """Create an SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    name = _xname(ctx, "q")
    sqs = ctx.client("sqs")
    resp = sqs.create_queue(QueueName=name, Attributes=dict(attrs), tags=_xsvc_resource_tags())
    url = resp["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    ctx.on_cleanup(_teardown(lambda: sqs.delete_queue(QueueUrl=url),
                              "AWS.SimpleQueueService.NonExistentQueue"))
    return {"name": name, "url": url, "arn": arn}


def _create_role(ctx, trust_service, inline_policy=None) -> dict[str, str]:
    """Create an IAM role and register its (policy-delete-then-role-delete) teardown."""
    iam = ctx.client("iam")
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
        )
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name: str) -> None:
    """IAM roles need every inline policy removed before deletion."""
    iam = ctx.client("iam")
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_pipe_role(ctx, source_arn: str, target_arn: str, extra=None) -> dict[str, str]:
    """The standard pipe execution role: read the source queue, send to the target queue."""
    statements = [
        {
            "Effect": "Allow",
            "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
            "Resource": source_arn,
        },
        {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": target_arn},
    ]
    statements.extend(extra or [])
    return _create_role(
        ctx, "pipes.amazonaws.com", {"Version": "2012-10-17", "Statement": statements}
    )


def _create_pipe(ctx, *, source: str, target: str, role_arn: str, desired_state="RUNNING",
                 wait_for="RUNNING", **extra) -> str:
    """Create a pipe and wait for CurrentState==wait_for; return the pipe name."""
    pipes = ctx.client("pipes")
    name = _xname(ctx, "pipe")
    # Retried only while the fresh execution role is not yet assumable by Pipes.
    timeout_s = _budget_s(ctx, 60.0)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            pipes.create_pipe(
                Name=name,
                RoleArn=role_arn,
                Source=source,
                Target=target,
                DesiredState=desired_state,
                Tags=_xsvc_resource_tags(),
                **extra,
            )
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            role_not_ready = code == "AccessDeniedException" or (
                code == "ValidationException"
                and ("cannot be assumed" in msg or "iam:PassRole" in msg)
            )
            if not role_not_ready:
                raise
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"pipe {name} was refused for its execution role for {timeout_s:.0f}s: {exc}"
                ) from exc
            time.sleep(5)
    ctx.on_cleanup(_teardown(lambda: pipes.delete_pipe(Name=name), "NotFoundException"))
    _poll_until(
        lambda: pipes.describe_pipe(Name=name).get("CurrentState"),
        lambda s: s == wait_for,
        timeout_s=_budget_s(ctx, 240.0),
        interval_s=5.0,
        description=f"pipe {name} {wait_for}",
    )
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
