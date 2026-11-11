"""assume-role-trust-policy-principal-arn-condition-enforced."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-trust-policy-principal-arn-condition-enforced"
GROUP = 'overly-permissive'
SERVICES = ['sts']
# What an error-code helper returns when the call succeeds: equal to no AWS error code.
_OK = "(no error: the call succeeded)"

# STS caches an ALLOW decision for a (role, calling principal) pair for ~5 minutes: after a trust
# policy is tightened, AssumeRole keeps succeeding for ~300s even though GetRole already returns
# the new document. Every poll that waits for a trust-policy edit has to outlast that cache.
_CACHE_DEADLINE_S = 600.0

@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A trust policy conditioned on aws:PrincipalArn: unconditional allows, pinned to another
    principal refuses with AccessDenied, pinned to the caller's own principal allows again --
    so the key is evaluated, not denied merely because a Condition block is present."""

    sts = ctx.client("sts")

    def _make_client_for(service):
        return ctx.client(service)

    def _error_code(fn):
        try:
            fn()
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")
        return _OK

    def _poll(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
        """Bounded poll to a condition; raises on deadline miss."""
        deadline = time.monotonic() + timeout_s
        while True:
            last = probe()
            if predicate(last):
                return last
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"{description} not reached within {timeout_s}s (last observed: {last!r})"
                )
            time.sleep(interval_s)

    identity_cache = {}

    def _identity():
        if not identity_cache:
            identity_cache.update(sts.get_caller_identity())
        return identity_cache

    def _account_id():
        return _identity()["Account"]

    def _caller_principal_arn():
        """The value real AWS puts in aws:PrincipalArn for this caller: for an assumed-role
        session that is the ROLE arn, not the assumed-role arn."""
        arn = _identity()["Arn"]
        if ":assumed-role/" in arn:
            role_name = arn.split(":assumed-role/", 1)[1].split("/", 1)[0]
            return f"arn:aws:iam::{_account_id()}:role/{role_name}"
        return arn

    def _tags_kv():
        return [
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ]

    def _trust_root(condition=None, actions=None):
        stmt = {
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{_account_id()}:root"},
            "Action": actions if actions is not None else ["sts:AssumeRole"],
        }
        if condition is not None:
            stmt["Condition"] = condition
        return {"Version": "2012-10-17", "Statement": [stmt]}

    def _allow(actions, resource="*", condition=None):
        stmt = {"Effect": "Allow", "Action": actions, "Resource": resource}
        if condition is not None:
            stmt["Condition"] = condition
        return {"Version": "2012-10-17", "Statement": [stmt]}

    def _drop_role(iam, role_name):
        # Attached managed policies and inline policies both block delete_role.
        for page in iam.get_paginator("list_attached_role_policies").paginate(RoleName=role_name):
            for pol in page.get("AttachedPolicies", []):
                iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
        for page in iam.get_paginator("list_role_policies").paginate(RoleName=role_name):
            for pname in page.get("PolicyNames", []):
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
        iam.delete_role(RoleName=role_name)
        _poll(
            lambda: _error_code(lambda: iam.get_role(RoleName=role_name)),
            lambda c: c == "NoSuchEntity", timeout_s=60.0, interval_s=2.0,
            description=f"role {role_name} disappeared",
        )

    def _create_role(iam, *, trust_policy, inline_policy=None, max_session_duration=3600):
        """Create a role, register its teardown immediately, return (name, arn, id)."""
        role_name = ctx.unique_name("sim2real-behav-sts-role-")
        created = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            MaxSessionDuration=max_session_duration,
            Tags=_tags_kv(),
        )["Role"]
        ctx.on_cleanup(lambda: _drop_role(iam, role_name))
        if inline_policy is not None:
            iam.put_role_policy(
                RoleName=role_name, PolicyName="sim2real-behav-inline",
                PolicyDocument=json.dumps(inline_policy),
            )
        return role_name, created["Arn"], created["RoleId"]

    def _try_assume(client, role_arn, session_name, seen=None, **kw):
        """The AssumeRole response dict on success, or the error code string on failure (so a
        code result also proves no credentials were issued)."""
        try:
            return client.assume_role(
                RoleArn=role_arn, RoleSessionName=session_name, **kw
            )
        except ClientError as exc:
            if seen is not None:
                seen["message"] = exc.response.get("Error", {}).get("Message")
            return exc.response.get("Error", {}).get("Code")

    def _wait_assumable(client, role_arn, session_name, **kw):
        # IAM trust-policy propagation: the first AssumeRole against a new or just-updated role
        # fails for seconds, so a negative must follow a positive control on the same role.
        return _poll(
            lambda: _try_assume(client, role_arn, session_name, **kw),
            lambda r: isinstance(r, dict),
            timeout_s=180.0, interval_s=3.0,
            description=f"role {role_arn} became assumable",
        )

    def _wait_assume_code(client, role_arn, session_name, expected, **kw):
        # A just-tightened trust policy keeps allowing until STS's ~5-minute cached decision
        # expires (refusal observed at ~302s), so the deadline is _CACHE_DEADLINE_S.
        seen = {}
        result = _poll(
            lambda: _try_assume(client, role_arn, session_name, seen, **kw),
            lambda r: r == expected,
            timeout_s=_CACHE_DEADLINE_S, interval_s=5.0,
            description=f"AssumeRole on {role_arn} began returning {expected}",
        )
        return result, seen.get("message")

    def _sess():
        return ctx.unique_name("sim2real-behav-sess-")

    iam = _make_client_for("iam")

    caller_arn = _caller_principal_arn()
    # A well-formed, in-account, nonexistent user ARN, so the request reaches policy evaluation.
    other_arn = f"arn:aws:iam::{_account_id()}:user/{ctx.unique_name('sim2real-behav-not-caller-')}"
    assert other_arn != caller_arn, other_arn

    role_name, role_arn, _role_id = _create_role(iam, trust_policy=_trust_root())

    # Positive control on the unconditional trust policy.
    _wait_assumable(sts, role_arn, _sess())

    # Pin aws:PrincipalArn to a principal that is NOT the caller.
    iam.update_assume_role_policy(
        RoleName=role_name,
        PolicyDocument=json.dumps(_trust_root(
            condition={"StringEquals": {"aws:PrincipalArn": other_arn}}
        )),
    )
    denied, denied_message = _wait_assume_code(sts, role_arn, _sess(), "AccessDenied")
    assert denied == "AccessDenied", (
        "a trust policy pinning aws:PrincipalArn to another principal must refuse this caller "
        f"with AccessDenied; got {denied!r} (no credentials may be issued)"
    )
    assert denied_message == (
        f"User: {_identity()['Arn']} is not authorized to perform: sts:AssumeRole on resource: "
        f"{role_arn}"
    ), denied_message

    # Pin aws:PrincipalArn to the caller's own principal: the assume must work again.
    iam.update_assume_role_policy(
        RoleName=role_name,
        PolicyDocument=json.dumps(_trust_root(
            condition={"StringEquals": {"aws:PrincipalArn": caller_arn}}
        )),
    )
    matched_sess = _sess()
    # Rewriting the condition to MATCH the caller is another trust-policy edit, so the
    # ~5-minute decision cache (see _CACHE_DEADLINE_S) applies in this direction too.
    allowed = _poll(
        lambda: _try_assume(sts, role_arn, matched_sess),
        lambda r: isinstance(r, dict), timeout_s=_CACHE_DEADLINE_S, interval_s=5.0,
        description="AssumeRole succeeded once aws:PrincipalArn matched the caller",
    )
    assert allowed["AssumedRoleUser"]["Arn"].endswith(
        f":assumed-role/{role_name}/{matched_sess}"
    ), allowed["AssumedRoleUser"]["Arn"]

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
