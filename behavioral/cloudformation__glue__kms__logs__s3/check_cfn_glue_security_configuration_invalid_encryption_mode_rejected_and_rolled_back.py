"""cfn-glue-security-configuration-invalid-encryption-mode-rejected-and-rolled-back."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-glue-security-configuration-invalid-encryption-mode-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "glue"]

#: A single-resource stack create or delete settles within a couple of minutes.
_STACK_S = 300.0
_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_NO_SEC_CONFIG = ("EntityNotFoundException", "")
#: Cloud Control wraps a registry handler's failure with a per-call RequestToken and the
#: handler's own error code; the quoted message is Glue's, masked of its own per-call ids.
_HANDLER_FAILURE = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A Glue CloudWatchEncryptionMode CloudFormation never validates locally is forwarded to
    Glue, which rejects it and rolls the stack back without creating the security configuration;
    the same template with a valid mode creates it (positive control).

    Reference: https://docs.aws.amazon.com/glue/latest/webapi/API_CloudWatchEncryption.html
    """
    cfn = ctx.client("cloudformation")
    glue = ctx.client("glue")

    broken_stack = ctx.unique_name("sim2real-cfnreal-gscmode-bad-")
    good_stack = ctx.unique_name("sim2real-cfnreal-gscmode-good-")
    name = ctx.unique_name("sim2real-cfnreal-gscmode-")

    limit: dict = {}
    ctx.on_cleanup(_teardown(lambda: glue.delete_security_configuration(Name=name), "EntityNotFoundException"))
    ctx.on_cleanup(lambda: _delete_stack(cfn, good_stack, limit))
    ctx.on_cleanup(lambda: _delete_stack(cfn, broken_stack, limit))

    # ---- the invalid mode is accepted by CloudFormation's local schema and refused by Glue ------
    stack_id = cfn.create_stack(
        StackName=broken_stack, Tags=_TAGS, TemplateBody=_template(name, "SSE-AES256")
    )["StackId"]
    failed = _settle(ctx, cfn, stack_id)
    assert failed["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"create ended {failed['StackStatus']!r}: {failed.get('StackStatusReason')!r}"
    )
    reasons = {
        e["LogicalResourceId"]: e.get("ResourceStatusReason")
        for e in _events(cfn, stack_id)
        if e["ResourceStatus"] == "CREATE_FAILED"
    }
    message, handler_code = _handler_failure(reasons.get("SecConfig"), ctx.account)
    want_message = (
        "1 validation error detected: Value 'SSE-AES256' at "
        "'encryptionConfiguration.cloudWatchEncryption.cloudWatchEncryptionMode' failed to "
        "satisfy constraint: Member must satisfy enum value set: [SSE-KMS, DISABLED] "
        "(Service: Glue, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)"
    )
    assert (message, handler_code) == (want_message, "InvalidRequest"), (
        f"CREATE_FAILED for SecConfig: {(message, handler_code)!r}, "
        f"expected {(want_message, 'InvalidRequest')!r}"
    )

    # effect absent: the security configuration the broken stack attempted was never created
    code, message = _error(lambda: glue.get_security_configuration(Name=name))
    assert (code, message) == _NO_SEC_CONFIG, (
        f"GetSecurityConfiguration after a rolled-back create: {(code, message)!r}, "
        f"expected {_NO_SEC_CONFIG!r}"
    )

    # ---- positive control: the identical template with a valid mode creates it -------------------
    stack_id = cfn.create_stack(
        StackName=good_stack, Tags=_TAGS, TemplateBody=_template(name, "DISABLED")
    )["StackId"]
    created = _settle(ctx, cfn, stack_id)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"create ended {created['StackStatus']!r}: {created.get('StackStatusReason')!r}"
    )
    cfg = glue.get_security_configuration(Name=name)["SecurityConfiguration"]
    assert cfg["EncryptionConfiguration"]["CloudWatchEncryption"] == {
        "CloudWatchEncryptionMode": "DISABLED"
    }, f"the valid-mode control must create the security configuration, got {cfg!r}"


def _template(name: str, mode: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "SecConfig": {
                    "Type": "AWS::Glue::SecurityConfiguration",
                    "Properties": {
                        "Name": name,
                        "EncryptionConfiguration": {
                            "CloudWatchEncryption": {"CloudWatchEncryptionMode": mode}
                        },
                    },
                }
            },
        }
    )


def _handler_failure(reason: str | None, account: str) -> tuple[str, str]:
    """(masked message, HandlerErrorCode) of a Cloud Control registry-handler failure reason."""
    m = _HANDLER_FAILURE.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    masked = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", m["message"])
    masked = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", masked)
    masked = masked.replace(account, "<account>")
    return masked, m["code"]


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn) -> tuple:
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _stack(cfn, stack_id: str) -> dict:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _events(cfn, stack_id: str) -> list[dict]:
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out[::-1]


def _poll(ctx, probe, done, *, cap_s: float, what: str, interval_s: float = 2.0):
    left = None if ctx is None else ctx.time_left()
    timeout_s = cap_s if left is None else max(1.0, min(cap_s, left - 5.0))
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            spent = left is not None and ctx.time_left() <= 6.0
            if spent:
                raise TimeoutError(f"the run budget ended while waiting for {what}; not graded")
            raise AssertionError(f"{what} not reached within {timeout_s:.0f}s; last {last!r}")
        time.sleep(interval_s)


def _settle(ctx, cfn, stack_id: str) -> dict:
    return _poll(
        ctx,
        lambda: _stack(cfn, stack_id),
        lambda s: not s["StackStatus"].endswith("_IN_PROGRESS"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} settled",
    )


def _remaining(limit: dict) -> float:
    deadline = limit.setdefault("at", time.monotonic() + 600.0)
    return max(1.0, deadline - time.monotonic())


def _delete_stack(cfn, stack_name: str, limit: dict) -> None:
    try:
        stack_id = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if exc.response["Error"].get("Message") == f"Stack with id {stack_name} does not exist":
            return
        raise
    status = _poll(
        None,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: not s.endswith("_IN_PROGRESS"),
        cap_s=_remaining(limit),
        what=f"stack {stack_id} settled before teardown",
    )
    if status in ("DELETE_COMPLETE", "ROLLBACK_COMPLETE"):
        if status == "ROLLBACK_COMPLETE":
            pass
        else:
            return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(
        None,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"),
        cap_s=_remaining(limit),
        what=f"stack {stack_id} deleted",
    )
    if final != "DELETE_COMPLETE":
        raise AssertionError(
            f"stack {stack_id} ended {final}: {_stack(cfn, stack_id).get('StackStatusReason')!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
