"""access-denied-without-permission-rejected."""
from __future__ import annotations

import json
import re
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "access-denied-without-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["nova-act"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An IAM principal with an explicit Deny on nova-act:* gets AccessDeniedException
    calling CreateWorkflowDefinition, and no resource is created. The very same call,
    made with the caller's normal (un-denied) credentials, succeeds (positive control)."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    nova = _nova_client(ctx)

    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-novaact-deny-")[:64]

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _silent(lambda: iam.delete_role(RoleName=role_name)))

    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": "nova-act:*", "Resource": "*"}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="deny-nova-act", PolicyDocument=json.dumps(deny_policy))
    ctx.on_cleanup(lambda: _silent(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="deny-nova-act")))

    session_name = ctx.unique_name("sim2real-sess-")[:32]
    creds = _assume_role_with_retry(sts, role_arn, session_name)

    denied_client = ctx.client(
        "nova-act",
        region="us-east-1",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    probe_name = _wf_name(ctx, "wfdeny")
    # Registered unconditionally, before the denied attempt: if the denied principal is in fact
    # over-permissive and creates the resource anyway, it must still be cleaned up rather than
    # leaking because the check's own success path never ran.
    ctx.on_cleanup(lambda: _silent(lambda: nova.delete_workflow_definition(workflowDefinitionName=probe_name)))

    def _attempt():
        return _error_code(lambda: denied_client.create_workflow_definition(name=probe_name, clientToken=_client_token()))

    code, message = _poll_until(
        _attempt, lambda r: r[0] == "AccessDeniedException", timeout_s=30.0, interval_s=3.0
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException from the denied principal, got {code!r}"
    assert message == (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name} is not authorized"
        f" to perform: nova-act:CreateWorkflowDefinition on resource:"
        f" arn:aws:nova-act:{nova.meta.region_name}:{account_id}:workflow-definition/{probe_name}"
        " with an explicit deny in an identity-based policy"
    ), f"unexpected access-denied message: {message!r}"

    # Effect absent: nothing got created under that name via the denied principal.
    not_found_code, not_found_message = _error_code(
        lambda: nova.get_workflow_definition(workflowDefinitionName=probe_name)
    )
    assert not_found_code == "ResourceNotFoundException", (
        f"denied create must leave no resource behind; get returned {not_found_code!r}"
    )
    assert not_found_message == "Workflow definition not found", f"unexpected not-found message: {not_found_message!r}"

    # Positive control, same file: the same call with normal credentials succeeds. The terminal
    # assertion is an independent read at the destination (GetWorkflowDefinition), not the
    # mutating call's own response.
    nova.create_workflow_definition(name=probe_name, clientToken=_client_token())
    got = nova.get_workflow_definition(workflowDefinitionName=probe_name)
    assert got["status"] == "ACTIVE", f"expected the un-denied create to leave an ACTIVE definition, got {got!r}"


def _nova_client(ctx):
    """Nova Act's control plane is served in us-east-1, so the client is pinned there; an
    emulator target ignores the region pin."""
    return ctx.client("nova-act", region="us-east-1")


def _wf_name(ctx, kind: str) -> str:
    raw = ctx.unique_name(f"n{kind}")
    return re.sub(r"[^a-zA-Z0-9_-]", "-", raw)[:40]


def _client_token() -> str:
    return uuid.uuid4().hex + "-" + uuid.uuid4().hex


def _assume_role_with_retry(sts, role_arn, session_name, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
        except Exception as exc:  # trust policy propagation can lag briefly
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"could not assume role {role_arn} within {timeout_s}s: {last_exc}")


def _error_code(fn) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        resp = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, call unexpectedly succeeded with {resp!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _silent(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFoundException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
