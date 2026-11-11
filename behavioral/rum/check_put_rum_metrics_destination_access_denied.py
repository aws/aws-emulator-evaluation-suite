"""put-rum-metrics-destination-access-denied."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-rum-metrics-destination-access-denied"
GROUP = "overly-permissive"
SERVICES = ["rum"]
_SESSION = "sim2real-behav"


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutRumMetricsDestination from a principal denied rum:PutRumMetricsDestination fails with
    AccessDeniedException, the destination is not persisted, and an unrestricted caller can
    still configure the same destination afterwards."""
    rum = ctx.client("rum")
    name = ctx.unique_name("sim2real-behav-appmon-")
    rum.create_app_monitor(Name=name, Domain="example.com", Tags={"Team": "rum-fidelity"})
    ctx.on_cleanup(lambda: _safe_delete_app_monitor(ctx, name))

    role_name = _create_denial_role(ctx, deny_actions=["rum:PutRumMetricsDestination"])
    creds = _assume_role_creds(ctx, f"arn:aws:iam::{ctx.account}:role/{role_name}")
    denied_rum = ctx.client("rum", creds=creds)

    # Positive control on the SAME role: rum:* is otherwise allowed, so a read must succeed once
    # the policy propagates. Without this, AccessDeniedException on the write below would be
    # indistinguishable from a role that cannot call any rum API at all.
    _poll_succeeds(lambda: denied_rum.list_rum_metrics_destinations(AppMonitorName=name), timeout_s=45.0)

    err = _poll_refused(
        lambda: denied_rum.put_rum_metrics_destination(AppMonitorName=name, Destination="CloudWatch"),
        timeout_s=45.0,
    )
    assert err["Code"] == "AccessDeniedException", f"expected AccessDeniedException, got {err!r}"
    expected_message = (
        f"User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/{_SESSION} is not authorized to "
        f"perform: rum:PutRumMetricsDestination on resource: "
        f"arn:aws:rum:{ctx.region}:{ctx.account}:appmonitor/{name} with an explicit deny in an "
        f"identity-based policy"
    )
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    destinations = rum.list_rum_metrics_destinations(AppMonitorName=name)["Destinations"]
    assert destinations == [], "denied PutRumMetricsDestination must not persist a destination"

    # Positive control: the unrestricted caller can configure the same destination.
    rum.put_rum_metrics_destination(AppMonitorName=name, Destination="CloudWatch")
    ctx.on_cleanup(
        lambda: rum.delete_rum_metrics_destination(AppMonitorName=name, Destination="CloudWatch")
    )
    result = _poll_until(
        lambda: rum.list_rum_metrics_destinations(AppMonitorName=name)["Destinations"],
        lambda d: len(d) == 1,
        timeout_s=30.0,
    )
    assert result[0]["Destination"] == "CloudWatch"


def _safe_delete_app_monitor(ctx, name: str) -> None:
    rum = ctx.client("rum")
    try:
        rum.delete_app_monitor(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_succeeds(fn, timeout_s=30.0, interval_s=2.0) -> None:
    """Retry fn() until it succeeds; raise with the last refusal on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            fn()
            return
        except ClientError as exc:
            last = exc.response["Error"]
        time.sleep(interval_s)
    raise AssertionError(f"call never succeeded within {timeout_s}s (last refusal={last!r})")


def _poll_refused(fn, timeout_s=30.0, interval_s=2.0) -> dict:
    """Retry fn() until it is refused with the role's policy fully visible and return the
    botocore Error dict. While IAM propagates, AWS can answer "because no identity-based policy
    allows ..." (the role's Allow is not yet visible); that form is retried. A call that keeps
    SUCCEEDING raises, so an over-permissive target cannot pass."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = fn()
        except ClientError as exc:
            last = exc.response["Error"]
            if "because no identity-based policy allows" not in (last.get("Message") or ""):
                return last
        time.sleep(interval_s)
    raise AssertionError(f"expected a settled refusal within {timeout_s}s, last={last!r}")


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_denial_role(ctx, deny_actions, allow_actions=("rum:*",)):
    iam = ctx.client("iam")
    account_id = ctx.account
    role_name = ctx.unique_name("sim2real-behav-deny-")
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
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    perm_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": list(allow_actions), "Resource": "*"},
            {"Effect": "Deny", "Action": list(deny_actions), "Resource": "*"},
        ],
    }
    policy_name = "denypolicy"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(perm_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_name


def _assume_role_creds(ctx, role_arn: str, timeout_s: float = 60.0):
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    last_err: Any = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION)["Credentials"]
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
