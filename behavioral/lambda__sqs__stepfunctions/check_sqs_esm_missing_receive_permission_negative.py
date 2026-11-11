"""sqs-esm-missing-receive-permission-negative."""

from __future__ import annotations

import json
import textwrap
import time
import zipfile
from io import BytesIO
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sqs-esm-missing-receive-permission-negative"

GROUP = "overly-permissive"

SERVICES = ["lambda", "stepfunctions", "sqs"]


def _esm_policy_statements(queue_arn: str, receive: bool) -> dict:
    """The inline policy for an ESM-target role: logs plus the SQS actions ESM needs, with
    sqs:ReceiveMessage present or withheld depending on `receive`."""
    actions = ["sqs:DeleteMessage", "sqs:GetQueueAttributes"]
    if receive:
        actions.insert(0, "sqs:ReceiveMessage")
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                "Resource": "arn:aws:logs:*:*:*",
            },
            {"Effect": "Allow", "Action": actions, "Resource": queue_arn},
        ],
    }


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Without sqs:ReceiveMessage on the role, CreateEventSourceMapping is refused with the exact ReceiveMessage
    permission message or the mapping never reaches Enabled, while a role with the action reaches Enabled; once the action is granted
    the same call succeeds and reaches Enabled.
    """
    queue = _create_queue(ctx)
    lmb = ctx.client("lambda")
    handler_code = """
def lambda_handler(event, context):
    return {'ok': True}
"""

    # ---- positive control: a role WITH sqs:ReceiveMessage reaches Enabled ----
    control_fn = _create_lambda(
        ctx,
        handler_code=handler_code,
        permissions=[
            {
                "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                "Resource": queue["arn"],
            },
        ],
    )
    control_esm = lmb.create_event_source_mapping(
        EventSourceArn=queue["arn"], FunctionName=control_fn["name"], BatchSize=10,
    )
    control_uuid = control_esm["UUID"]
    ctx.on_cleanup(lambda: _delete_esm_if_present(lmb, control_uuid))
    control_state = _poll_until(
        lambda: lmb.get_event_source_mapping(UUID=control_uuid),
        lambda e: e["State"] not in ("Creating", "Enabling"),
        timeout_s=90,
        interval_s=3,
        description="control ESM (full permissions) settling",
    )["State"]
    assert control_state == "Enabled", (
        f"control ESM with sqs:ReceiveMessage granted did not reach Enabled, got "
        f"state={control_state!r} — the account/pipeline is not healthy enough for this "
        f"negative to mean anything"
    )

    # ---- break exactly one thing: the same shape of role, minus sqs:ReceiveMessage ----
    broken_role = _create_role(
        ctx,
        "lambda.amazonaws.com",
        inline_policy=_esm_policy_statements(queue["arn"], receive=False),
    )
    broken_fn = _create_function_with_retry(ctx, handler_code, broken_role["arn"], {})

    def _create_broken_esm():
        return lmb.create_event_source_mapping(
            EventSourceArn=queue["arn"], FunctionName=broken_fn["name"], BatchSize=10,
        )

    esm_uuid = None
    try:
        esm = _create_broken_esm()
    except lmb.exceptions.InvalidParameterValueException as e:
        expected_message = "The function execution role does not have permissions to call ReceiveMessage on SQS"
        assert e.response["Error"]["Message"] == expected_message, (
            f"expected the refusal {expected_message!r} (so this negative is not indistinguishable "
            f"from any other InvalidParameterValueException), got: {e}"
        )
    else:
        esm_uuid = esm["UUID"]
        ctx.on_cleanup(lambda: _delete_esm_if_present(lmb, esm_uuid))
        state = _poll_until(
            lambda: lmb.get_event_source_mapping(UUID=esm_uuid),
            lambda e: e["State"] not in ("Creating", "Enabling"),
            # >=3x the control leg's own settle latency, not a bare sleep.
            timeout_s=270,
            interval_s=5,
            description="broken ESM (missing ReceiveMessage) settling",
        )["State"]
        assert state != "Enabled", (
            f"ESM reached Enabled state without sqs:ReceiveMessage on the execution role, "
            f"got state={state!r}"
        )
        mappings = lmb.list_event_source_mappings(
            EventSourceArn=queue["arn"], FunctionName=broken_fn["name"],
        )["EventSourceMappings"]
        assert mappings and all(m["State"] != "Enabled" for m in mappings), (
            f"list_event_source_mappings shows an Enabled mapping despite the missing "
            f"permission: {mappings!r}"
        )
        lmb.delete_event_source_mapping(UUID=esm_uuid)
        _poll_until(
            lambda: lmb.list_event_source_mappings(
                EventSourceArn=queue["arn"], FunctionName=broken_fn["name"]
            )["EventSourceMappings"],
            lambda ms: not ms,
            timeout_s=60,
            interval_s=3,
            description="broken ESM deleted before the restore leg re-creates it",
        )

    # ---- restore: grant the missing action to the SAME role, then the identical call succeeds ----
    ctx.client("iam").put_role_policy(
        RoleName=broken_role["name"],
        PolicyName="inline",
        PolicyDocument=json.dumps(_esm_policy_statements(queue["arn"], receive=True)),
    )
    deadline = time.monotonic() + 30
    restored = None
    last_err = None
    while restored is None and time.monotonic() < deadline:
        try:
            restored = _create_broken_esm()
        except lmb.exceptions.InvalidParameterValueException as e:
            last_err = e
            time.sleep(3)  # bounded retry through IAM policy propagation, not a bare sleep
    assert restored is not None, (
        f"the identical create_event_source_mapping call was still refused after granting "
        f"sqs:ReceiveMessage to the same role: {last_err}"
    )
    restored_uuid = restored["UUID"]
    ctx.on_cleanup(lambda: _delete_esm_if_present(lmb, restored_uuid))
    restored_state = _poll_until(
        lambda: lmb.get_event_source_mapping(UUID=restored_uuid),
        lambda e: e["State"] not in ("Creating", "Enabling"),
        timeout_s=90,
        interval_s=3,
        description="restored ESM (permission granted) settling",
    )["State"]
    assert restored_state == "Enabled", (
        f"the identical call did not reach Enabled after granting sqs:ReceiveMessage on the "
        f"same role, got state={restored_state!r} — the earlier refusal cannot be attributed "
        f"to the missing permission"
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


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _create_role(
    ctx, trust_service, inline_policy=None, managed_policies=None
) -> dict[str, str]:
    """Create an IAM role and register its (policy-detach-then-delete) teardown. Returns {name,arn}."""
    iam = ctx.client("iam")
    role_name = _xname(ctx, f"role-{trust_service.split('.')[0]}")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trust_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    for policy_arn in managed_policies or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="inline",
            PolicyDocument=json.dumps(inline_policy),
        )
    # No unconditional sleep for propagation: _create_function_with_retry already retries
    # create_function through the assume-role propagation window with a bounded deadline, and
    # every other caller of this role goes through a create-and-poll-to-Active round trip first,
    # which itself takes longer than IAM propagation.
    return {"name": role_name, "arn": resp["Role"]["Arn"]}


def _delete_role(ctx, role_name: str) -> None:
    """IAM roles need every attached + inline policy removed before deletion."""
    iam = ctx.client("iam")
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get(
            "AttachedPolicies", []
        ):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
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


def _wait_function_active(ctx, name: str, timeout_s: float = 60) -> None:
    lam = ctx.client("lambda")
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda r: r.get("State") == "Active",
        timeout_s=timeout_s,
        interval_s=2.0,
        description=f"Lambda {name} active",
    )


def _create_function_with_retry(
    ctx, handler_code, role_arn, env, timeout=30, memory=128, runtime="python3.12"
) -> dict[str, str]:
    """Create a Lambda, retrying through the IAM role-propagation window, then wait until Active.
    Registers the function's teardown (LIFO-before its role, since the role was registered first)."""
    name = _xname(ctx, "fn")
    lam = ctx.client("lambda")
    # Normalize inline handler source: dedent (checks often embed indented triple-quoted code) and
    # bind to the fixed entrypoint — the Handler is "lambda_function.lambda_handler", but inline code
    # is conventionally written as `def handler(event, context)`. Without a lambda_handler symbol the
    # function fails at runtime with Runtime.HandlerNotFound before any behavior is exercised. Both are
    # no-ops for code that's already column-0 and defines lambda_handler.
    handler_code = textwrap.dedent(handler_code)
    if "def lambda_handler" not in handler_code and "def handler" in handler_code:
        handler_code = handler_code.rstrip() + "\n\nlambda_handler = handler\n"
    zip_buf = BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    kwargs: dict[str, Any] = {
        "FunctionName": name,
        "Runtime": runtime,
        "Role": role_arn,
        "Handler": "lambda_function.lambda_handler",
        "Code": {"ZipFile": zip_buf.getvalue()},
        "Timeout": timeout,
        "MemorySize": memory,
        "Tags": dict(_xsvc_resource_tags()),
    }
    if env:
        kwargs["Environment"] = {"Variables": env}
    deadline = time.monotonic() + 30
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_function(**kwargs)
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
            # The function creates /aws/lambda/<name> on its first invoke and the group outlives the
            # function; a function that never ran has none.
            ctx.on_cleanup(lambda: _delete_log_group_if_present(ctx, f"/aws/lambda/{name}"))
            _wait_function_active(ctx, name)
            return {"name": name, "arn": resp["FunctionArn"]}
        except ClientError as e:
            if "cannot be assumed" in str(e) or "InvalidParameterValue" in str(e):
                last_err = e
                time.sleep(3)
                continue
            raise
    raise last_err or RuntimeError(f"Failed to create Lambda {name}")


def _create_lambda(
    ctx,
    handler_code,
    permissions=None,
    env=None,
    timeout=30,
    memory=128,
    runtime="python3.12",
) -> dict[str, str]:
    """Create a Lambda with an execution role scoped to `permissions` (a list of IAM statement
    fragments like [{"Action": ["sqs:SendMessage"], "Resource": queue_arn}]); logs are always
    allowed. Role + function each register their own teardown (function torn down first, LIFO).
    Returns {name,arn}."""
    statements = [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
            ],
            "Resource": "arn:aws:logs:*:*:*",
        }
    ]
    for perm in permissions or []:
        actions = (
            perm["Action"] if isinstance(perm["Action"], list) else [perm["Action"]]
        )
        resource = (
            perm["Resource"]
            if isinstance(perm["Resource"], list)
            else [perm["Resource"]]
        )
        statements.append({"Effect": "Allow", "Action": actions, "Resource": resource})
    role = _create_role(
        ctx,
        "lambda.amazonaws.com",
        inline_policy={"Version": "2012-10-17", "Statement": statements},
    )
    return _create_function_with_retry(
        ctx, handler_code, role["arn"], env or {}, timeout, memory, runtime
    )


def _create_queue(ctx, fifo: bool = False, **attrs: str) -> dict[str, str]:
    """Create an SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    base = _xname(ctx, "q")
    name = f"{base}.fifo" if fifo else base
    sqs = ctx.client("sqs")
    create_attrs = dict(attrs)
    if fifo:
        create_attrs["FifoQueue"] = "true"
    resp = sqs.create_queue(
        QueueName=name, Attributes=create_attrs, tags=_xsvc_resource_tags()
    )
    url = resp["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return {"name": name, "url": url, "arn": arn}


def _delete_log_group_if_present(ctx, log_group: str) -> None:
    try:
        ctx.client("logs").delete_log_group(logGroupName=log_group)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_esm_if_present(lam, esm_uuid: str) -> None:
    """DeleteEventSourceMapping; a mapping the check already deleted answers ResourceNotFoundException."""
    try:
        lam.delete_event_source_mapping(UUID=esm_uuid)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
