"""resource-policy-enforced-on-put-rum-events."""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-enforced-on-put-rum-events"
GROUP = "server-side"
SERVICES = ["rum"]


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutRumEvents from a principal with no rum permissions is denied with the exact AccessDenied
    message, succeeds once the app monitor's resource policy grants it rum:PutRumEvents, and is denied
    again after the policy is deleted: the resource policy is evaluated on every call."""
    rum = ctx.client("rum")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    partition = sts.get_caller_identity()["Arn"].split(":")[1]

    name = ctx.unique_name("sim2real-behav-appmon-")
    monitor_id = rum.create_app_monitor(
        Name=name, Domain="example.com", Tags={"sim2real-check": CHECK}
    )["Id"]
    ctx.on_cleanup(lambda: _safe_delete_app_monitor(ctx, name))
    monitor_arn = f"arn:{partition}:rum:{ctx.region}:{account_id}:appmonitor/{name}"

    bare_role_arn = _create_bare_role(ctx)
    creds = _assume_role_creds(ctx, bare_role_arn)
    bare_rum = ctx.client("rum", creds=creds)

    def attempt():
        return _poll_past_transient_creds(
            lambda: _error_code(lambda: bare_rum.put_rum_events(**_rum_event_kwargs(monitor_id)))
        )

    denied = (
        f"User: arn:{partition}:sts::{account_id}:assumed-role/{bare_role_arn.rsplit('/', 1)[-1]}/"
        f"sim2real-behav is not authorized to perform: rum:PutRumEvents on resource: {monitor_id} "
        "because no identity-based policy allows the rum:PutRumEvents action"
    )
    code_before = _poll_until(attempt, lambda c: c is not None, timeout_s=45.0)
    assert code_before is not None and "AccessDenied" in code_before[0], (
        f"expected an AccessDenied-family error before any grant, got {code_before!r}"
    )
    assert code_before[1] == denied, f"expected message {denied!r}, got {code_before[1]!r}"

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": bare_role_arn},
                "Action": "rum:PutRumEvents",
                "Resource": monitor_arn,
            }
        ],
    }
    rum.put_resource_policy(Name=name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: _safe_delete_resource_policy(ctx, name))

    code_after_grant = _poll_until(attempt, lambda c: c is None, timeout_s=120.0)
    assert code_after_grant is None, "PutRumEvents should succeed once the resource policy grants it"

    rum.delete_resource_policy(Name=name)

    code_after_revoke = _poll_until(attempt, lambda c: c is not None, timeout_s=120.0)
    assert code_after_revoke is not None and "AccessDenied" in code_after_revoke[0], (
        f"expected an AccessDenied-family error after policy revoke, got {code_after_revoke!r}"
    )
    assert code_after_revoke[1] == denied, f"expected message {denied!r}, got {code_after_revoke[1]!r}"


def _rum_event_kwargs(monitor_id: str) -> dict:
    return {
        "Id": monitor_id,
        "BatchId": str(uuid.uuid4()),
        "AppMonitorDetails": {
            "id": "sim2real-behav",
            "name": "sim2real-behav",
            "version": "1.0.0",
        },
        "UserDetails": {"sessionId": str(uuid.uuid4()), "userId": str(uuid.uuid4())},
        "RumEvents": [
            {
                "id": str(uuid.uuid4()),
                "timestamp": datetime.now(timezone.utc),
                "type": "com.amazon.rum.custom_event",
                "details": json.dumps({"version": "1.0.0"}),
                "metadata": json.dumps({"version": "1.0.0", "domain": "example.com"}),
            }
        ],
    }


def _safe_delete_app_monitor(ctx, name: str) -> None:
    rum = ctx.client("rum")
    try:
        rum.delete_app_monitor(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_resource_policy(ctx, name: str) -> None:
    rum = ctx.client("rum")
    try:
        rum.delete_resource_policy(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("PolicyNotFoundException", "ResourceNotFoundException"):
            raise


def _error_code(fn):
    """The (code, message) of the ClientError fn raises, or None when the call is accepted."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    return None


_TRANSIENT_CRED_ERRORS = ("UnrecognizedClientException", "InvalidClientTokenId")


def _poll_past_transient_creds(probe, timeout_s=20.0, interval_s=2.0):
    """A just-assumed role's temporary credentials can take a few seconds to be recognized
    by a service other than the one that minted them; retry only that specific transient
    class -- an AccessDenied (or any other outcome) is a real answer and returns immediately."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if last is None or last[0] not in _TRANSIENT_CRED_ERRORS:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"credentials still unrecognized after {timeout_s}s (last={last!r})")


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_bare_role(ctx):
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-behav-bare-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _assume_role_creds(ctx, role_arn: str, timeout_s: float = 60.0):
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last_err: Any = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-behav")["Credentials"]
            return {
                "aws_access_key_id": creds["AccessKeyId"],
                "aws_secret_access_key": creds["SecretAccessKey"],
                "aws_session_token": creds["SessionToken"],
            }
        except ClientError as exc:
            last_err = exc
            time.sleep(2.0)
    raise AssertionError(f"could not assume role {role_arn}: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
