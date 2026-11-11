"""delete-resource-in-use-blocked."""

from __future__ import annotations

import io
import json
import os
import textwrap
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "delete-resource-in-use-blocked"
GROUP = 'lifecycle'
SERVICES = ['lambda']

HANDLER_V1 = "def handler(event, context): return {'marker': 'v1', 'echo': event}"
HANDLER_V2 = "def handler(event, context): return {'marker': 'v2', 'echo': event}"


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


_ROLE_ARNS: dict = {}


def _role_arn(ctx):
    key = id(ctx)
    if key not in _ROLE_ARNS:
        iam = ctx.client("iam")
        role_name = ctx.unique_name("sim2real-behav-role-")
        trust = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
        role = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust),
            Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        )
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
        # The SQS event source mapping in sub-part (1) needs the role to poll the queue.
        poll_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "sqs:ReceiveMessage",
                        "sqs:DeleteMessage",
                        "sqs:GetQueueAttributes",
                        "sqs:ChangeMessageVisibility",
                    ],
                    "Resource": "*",
                },
                {
                    "Effect": "Allow",
                    "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                    "Resource": "*",
                },
            ],
        }
        iam.put_role_policy(
            RoleName=role_name, PolicyName="sim2real-sqs-poll", PolicyDocument=json.dumps(poll_policy)
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-sqs-poll"))
        _ROLE_ARNS[key] = role["Role"]["Arn"]
    return _ROLE_ARNS[key]


def _create_function_retrying(lam, kwargs, timeout_s=60):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if (
                err.get("Code") == "InvalidParameterValueException"
                and "cannot be assumed" in err.get("Message", "")
                and time.monotonic() < deadline
            ):
                time.sleep(3)
                continue
            raise


def _cleanup_fn(ctx, lam, name):
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_active(lam, fn, timeout_s=60):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=fn)
        if last["State"] == "Failed":
            raise AssertionError(f"Function {fn} entered Failed: {last.get('StateReason')}")
        if last["State"] == "Active":
            return
        time.sleep(1.0)
    raise AssertionError(f"{fn} Active not met within {timeout_s}s. Last: {last!r}")


def _wait_update_settled(lam, fn, timeout_s=60):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if lam.get_function_configuration(FunctionName=fn).get("LastUpdateStatus") in ("Successful", "Failed", None):
            return
        time.sleep(1.0)


def _deploy_function(ctx, lam, code, *, name=None):
    name = name or ctx.unique_name("sim2real-behav-fn-")
    _create_function_retrying(lam, dict(
        FunctionName=name,
        Runtime="python3.12",
        Handler="index.handler",
        Role=_role_arn(ctx),
        Code={"ZipFile": _make_zip(code)},
        MemorySize=128,
        Timeout=30,
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    ))
    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    _wait_active(lam, name)
    return name


_SUCCEEDED = "<call succeeded>"


def _attempt(fn):
    """(code, message) of a refused call, or (_SUCCEEDED, None) when it succeeds; no error code
    equals _SUCCEEDED, so a success never reads as a code."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    return _SUCCEEDED, None


def _client_error(fn):
    """(code, message) of a call that must be refused; raises if the call succeeds."""
    code, msg = _attempt(fn)
    if code == _SUCCEEDED:
        raise AssertionError("expected the call to be rejected, but it succeeded")
    return code, msg


def _tolerate_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _is_esm_role_perm_error(exc):
    """CreateEventSourceMapping validates that the function's execution role can poll the source
    (e.g. sqs:ReceiveMessage). The role holds those grants, so this refusal only means the new
    grant has not propagated yet; it is retried for a bounded time."""
    if not isinstance(exc, ClientError):
        return False
    err = exc.response.get("Error", {})
    msg = err.get("Message", "")
    return err.get("Code") == "InvalidParameterValueException" and (
        "does not have permissions" in msg or "ReceiveMessage" in msg
    )


def _wait_esm_gone(lam, uuid_, timeout_s=180):
    """Poll GetEventSourceMapping until the accepted delete completes (State Deleting while it
    runs); return the refusal's (code, message), raising if the mapping never goes away."""
    deadline = time.monotonic() + timeout_s
    while True:
        code, msg = _attempt(lambda: lam.get_event_source_mapping(UUID=uuid_))
        if code != _SUCCEEDED:
            return code, msg
        if time.monotonic() >= deadline:
            raise AssertionError(f"event source mapping {uuid_} still readable {timeout_s}s after its delete")
        time.sleep(5)


def _wait_esm_settled(lam, uuid_, timeout_s=90):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            st = lam.get_event_source_mapping(UUID=uuid_).get("State")
        except ClientError:
            return
        if st not in (None, "Creating"):
            return
        time.sleep(3.0)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteEventSourceMapping mid-Creating, DeleteFunction mid code update, and DeleteAlias with
    provisioned concurrency each either succeed or are refused with a conflict, then read back gone.

    Reference: https://docs.aws.amazon.com/lambda/latest/api/API_DeleteFunction.html
    """
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")
    conflict_codes = {"ResourceInUseException", "ResourceConflictException"}

    # --- (3) DeleteAlias with a dependent ProvisionedConcurrencyConfig ---
    # Real AWS does not block this by default.
    fn = _deploy_function(ctx, lam, HANDLER_V1)
    fn_arn = lam.get_function_configuration(FunctionName=fn)["FunctionArn"]
    v1 = lam.publish_version(FunctionName=fn)["Version"]
    alias_name = "sim2real-behav-pc-alias"
    alias_missing_msg = f"Cannot find alias arn: {fn_arn}:{alias_name}"
    lam.create_alias(FunctionName=fn, Name=alias_name, FunctionVersion=v1)
    lam.put_provisioned_concurrency_config(
        FunctionName=fn, Qualifier=alias_name, ProvisionedConcurrentExecutions=1
    )
    ctx.on_cleanup(
        lambda: _tolerate_not_found(
            lambda: lam.delete_provisioned_concurrency_config(FunctionName=fn, Qualifier=alias_name)
        )
    )

    alias_delete_code, _ = _attempt(lambda: lam.delete_alias(FunctionName=fn, Name=alias_name))
    if alias_delete_code == _SUCCEEDED:
        gone_code, gone_msg = _client_error(lambda: lam.get_alias(FunctionName=fn, Name=alias_name))
        assert gone_code == "ResourceNotFoundException", (
            f"expected the alias to be gone after a successful delete, got {gone_code}"
        )
        assert gone_msg == alias_missing_msg, f"expected message {alias_missing_msg!r}, got {gone_msg!r}"
        pc_code, pc_msg = _attempt(
            lambda: lam.delete_provisioned_concurrency_config(FunctionName=fn, Qualifier=alias_name)
        )
        if pc_code != _SUCCEEDED:
            assert pc_code == "ResourceNotFoundException", pc_code
            assert pc_msg == alias_missing_msg, f"expected message {alias_missing_msg!r}, got {pc_msg!r}"
    else:
        # No message asserted: AWS takes the success branch, so there is no refusal to compare.
        assert alias_delete_code in conflict_codes, (
            f"expected one of {conflict_codes} deleting an alias with an attached provisioned-concurrency "
            f"config, got {alias_delete_code}"
        )
        lam.delete_provisioned_concurrency_config(FunctionName=fn, Qualifier=alias_name)
        lam.delete_alias(FunctionName=fn, Name=alias_name)
        gone_code, gone_msg = _client_error(lambda: lam.get_alias(FunctionName=fn, Name=alias_name))
        assert gone_code == "ResourceNotFoundException", gone_code
        assert gone_msg == alias_missing_msg, f"expected message {alias_missing_msg!r}, got {gone_msg!r}"

    # --- (1) DeleteEventSourceMapping mid-"Creating" ---
    # A narrow timing window: either blocked or deleted is accepted, then read back.
    # Creating an SQS event source mapping requires the exec role to hold SQS polling
    # permissions; the role this check creates holds them.
    q_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-esm-inuse-q-"),
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=q_url))
    q_arn = sqs.get_queue_attributes(QueueUrl=q_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    esm_uuid = None
    esm_deadline = time.monotonic() + 90
    while esm_uuid is None:
        try:
            esm = lam.create_event_source_mapping(FunctionName=fn, EventSourceArn=q_arn, Enabled=True)
            esm_uuid = esm["UUID"]
        except ClientError as exc:
            if not _is_esm_role_perm_error(exc) or time.monotonic() >= esm_deadline:
                raise
            time.sleep(5)
    if esm_uuid is not None:
        ctx.on_cleanup(
            lambda: _tolerate_not_found(lambda: lam.delete_event_source_mapping(UUID=esm_uuid))
        )
        esm_missing_msg = "The resource you requested does not exist."

        esm_delete_code, _ = _attempt(lambda: lam.delete_event_source_mapping(UUID=esm_uuid))
        if esm_delete_code == _SUCCEEDED:
            gone_code, gone_msg = _wait_esm_gone(lam, esm_uuid)
            assert gone_code == "ResourceNotFoundException", (
                f"expected the mid-Creating ESM to be gone after a successful delete, got {gone_code}"
            )
            assert gone_msg == esm_missing_msg, f"expected message {esm_missing_msg!r}, got {gone_msg!r}"
        else:
            # No message asserted: AWS takes the success branch, so there is no refusal to compare.
            assert esm_delete_code in conflict_codes, (
                f"expected one of {conflict_codes} deleting a mid-Creating ESM, got {esm_delete_code}"
            )
            _wait_esm_settled(lam, esm_uuid)
            try:
                lam.delete_event_source_mapping(UUID=esm_uuid)
            except ClientError:
                pass
            gone_code, gone_msg = _wait_esm_gone(lam, esm_uuid)
            assert gone_code == "ResourceNotFoundException", gone_code
            assert gone_msg == esm_missing_msg, f"expected message {esm_missing_msg!r}, got {gone_msg!r}"

    # --- (2) DeleteFunction mid code-update (Pending/InProgress) ---
    # ~10 MB of padding keeps the update in progress; real AWS lets the delete proceed.
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("index.py", HANDLER_V2)
        zf.writestr("padding.bin", os.urandom(10 * 1024 * 1024))
    lam.update_function_code(FunctionName=fn, ZipFile=buf.getvalue())

    fn_missing_msg = f"Function not found: {fn_arn}"
    fn_delete_code, _ = _attempt(lambda: lam.delete_function(FunctionName=fn))
    if fn_delete_code == _SUCCEEDED:
        gone_code, gone_msg = _client_error(lambda: lam.get_function_configuration(FunctionName=fn))
        assert gone_code == "ResourceNotFoundException", (
            f"expected the function to be gone after a successful delete mid-update, got {gone_code}"
        )
        assert gone_msg == fn_missing_msg, f"expected message {fn_missing_msg!r}, got {gone_msg!r}"
    else:
        # No message asserted: AWS takes the success branch, so there is no refusal to compare.
        assert fn_delete_code in conflict_codes, (
            f"expected one of {conflict_codes} deleting a function mid-update, got {fn_delete_code}"
        )
        _wait_update_settled(lam, fn)
        try:
            lam.delete_function(FunctionName=fn)
        except ClientError:
            pass
        gone_code, gone_msg = _client_error(lambda: lam.get_function_configuration(FunctionName=fn))
        assert gone_code == "ResourceNotFoundException", gone_code
        assert gone_msg == fn_missing_msg, f"expected message {fn_missing_msg!r}, got {gone_msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
