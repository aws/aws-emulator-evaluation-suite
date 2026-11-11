"""explicit-deny-overrides-broad-allow-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "explicit-deny-overrides-broad-allow-rejected"
GROUP = "overly-permissive"
SERVICES = ["bcm-recommended-actions"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A role with ReadOnlyAccess and an inline Allow on bcm-recommended-actions:* can call
    ListRecommendedActions until an explicit inline Deny is added, then gets AccessDeniedException with
    the exact message while sts:GetCallerIdentity still works, and recovers once the Deny is deleted."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-bcmra-explicitdeny-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/ReadOnlyAccess")
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/ReadOnlyAccess"))

    # ReadOnlyAccess does not grant bcm-recommended-actions actions, so the broad Allow this
    # check exists to test is made explicit here.
    allow_policy_name = ctx.unique_name("sim2real-bcmra-allowpolicy-")
    allow_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "bcm-recommended-actions:*", "Resource": "*"},
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=allow_policy_name, PolicyDocument=json.dumps(allow_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=allow_policy_name))

    restricted = _assume_role_client(ctx, role_arn, "bcm-recommended-actions")
    restricted_sts = _assume_role_client(ctx, role_arn, "sts")

    # Positive control, captured BEFORE anything is denied, on the SAME role that will be denied
    # below.
    before = _poll_for_success(lambda: restricted.list_recommended_actions())
    assert "recommendedActions" in before, (
        f"positive control: the ReadOnlyAccess-only role must be able to call "
        f"ListRecommendedActions before any Deny exists; got {before!r}"
    )

    deny_policy_name = ctx.unique_name("sim2real-bcmra-denypolicy-")
    deny_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Deny", "Action": "bcm-recommended-actions:ListRecommendedActions", "Resource": "*"},
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=deny_policy_name, PolicyDocument=json.dumps(deny_policy))
    ctx.on_cleanup(lambda: _drop_deny(iam, role_name, deny_policy_name))

    error = _poll_for_denial(lambda: restricted.list_recommended_actions())
    assert error.get("Code") == "AccessDeniedException", (
        f"an explicit Deny on ListRecommendedActions must reject with AccessDeniedException "
        f"even though the role also carries the broad ReadOnlyAccess allow; got {error.get('Code')!r}"
    )
    partition = role_arn.split(":")[1]
    expected_message = (
        f"User: arn:{partition}:sts::{account_id}:assumed-role/{role_name}/sim2real-bcmra-check "
        "is not authorized to perform: bcm-recommended-actions:ListRecommendedActions with an "
        "explicit deny in an identity-based policy"
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # The explicit Deny is scoped: an unrelated call on the same role/creds
    # still works, proving this is not a broken/unauthenticated identity.
    identity = restricted_sts.get_caller_identity()
    assert identity["Arn"].endswith(f"/{role_name}/sim2real-bcmra-check"), (
        f"the Deny must be scoped to ListRecommendedActions only -- an unrelated call "
        f"(sts:GetCallerIdentity) on the same role/credentials must still succeed with a "
        f"matching ARN; got {identity['Arn']!r}"
    )

    # Restore: delete the Deny and demand the SAME role recover, proving the Deny -- not
    # something else about the role or account -- was the cause of the denial above.
    _drop_deny(iam, role_name, deny_policy_name)
    restored = _poll_for_success(lambda: restricted.list_recommended_actions())
    assert "recommendedActions" in restored, (
        f"deleting the Deny must restore ListRecommendedActions on the SAME restricted role; "
        f"got {restored!r}"
    )


def _poll_for_denial(fn, timeout_s: float = 30.0, interval_s: float = 2.0) -> dict:
    """Poll `fn` until it raises AccessDeniedException and return that botocore Error dict,
    tolerating the brief propagation lag between IAM policy attachment and a freshly assumed
    role's authorization taking effect. Raises on timeout, naming the last success or error."""
    deadline = time.monotonic() + timeout_s
    last: object = None
    while time.monotonic() < deadline:
        try:
            last = fn()
        except ClientError as exc:
            error = exc.response.get("Error", {})
            if error.get("Code") == "AccessDeniedException":
                return error
            last = error
        time.sleep(interval_s)
    raise AssertionError(
        f"an explicit Deny on ListRecommendedActions was never enforced within {timeout_s}s; "
        f"last observation: {last!r}"
    )


def _poll_for_success(fn, timeout_s: float = 30.0, interval_s: float = 2.0):
    """Poll `fn` until it stops raising, tolerating the brief propagation lag between an IAM
    policy change (attach or delete) and a freshly assumed role's authorization actually taking
    effect. Raises the last observed error on timeout rather than returning a stale value."""
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    assert last_exc is not None
    raise last_exc


def _drop_deny(iam, role_name: str, deny_policy_name: str) -> None:
    """Teardown-only: the body deletes this policy itself, so tolerate it already being gone."""
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=deny_policy_name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


def _assume_role_client(ctx, role_arn: str, service: str):
    """Assume `role_arn` (retrying past IAM trust-policy propagation delay)
    and return a client for `service` using those temporary credentials.
    ctx.client's creds override keeps the check's endpoint and TLS settings while
    signing with the assumed-role identity, so the call reaches the same endpoint
    as every other client of the check."""
    sts = ctx.client("sts")
    last_exc: ClientError | None = None
    for _ in range(10):
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-bcmra-check")["Credentials"]
            return ctx.client(
                service,
                creds={
                    "aws_access_key_id": creds["AccessKeyId"],
                    "aws_secret_access_key": creds["SecretAccessKey"],
                    "aws_session_token": creds["SessionToken"],
                },
            )
        except ClientError as exc:
            last_exc = exc
            time.sleep(2)
    assert last_exc is not None
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
