"""assume-role-session-tag-decides-policy-condition."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-session-tag-decides-policy-condition"
GROUP = 'overly-permissive'
SERVICES = ['sts']
# What an error-code helper returns when the call succeeds: equal to no AWS error code.
_OK = "(no error: the call succeeded)"

@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An AssumeRole session tag becomes aws:PrincipalTag/<key> and decides a session-policy
    condition: matching value allows, mismatched value denies, absent tag denies. The allow case
    rules out a target that denies whenever it sees a condition key it does not understand."""

    sts = ctx.client("sts")

    # Minted credentials are passed only as ctx.client(creds=...) arguments, never via
    # os.environ, where they would shadow the ambient credentials of later checks.

    def _make_client_for(service):
        return ctx.client(service)

    def _client_with_credentials(service, creds):
        return ctx.client(service, creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds.get("SessionToken"),
        })

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


    def _poll_allowed(fn, *, timeout_s=120.0, what="call"):
        """Poll until fn() succeeds, so a transient InvalidClientTokenId or an unpropagated
        policy is not read as a denial."""
        return _poll(
            lambda: _error_code(fn), lambda c: c == _OK,
            timeout_s=timeout_s, interval_s=3.0,
            description=f"{what} became permitted",
        )

    def _poll_denied(fn, expected, *, timeout_s=60.0, what="call"):
        """Poll until fn() fails with exactly `expected`, returning (code, message). Called only after a positive control
        has proven the credential live and the policy propagated, so the deadline is short."""
        seen = {}

        def _probe():
            try:
                fn()
            except ClientError as exc:
                seen["message"] = exc.response.get("Error", {}).get("Message")
                return exc.response.get("Error", {}).get("Code")
            return _OK

        code = _poll(
            _probe, lambda c: c == expected,
            timeout_s=timeout_s, interval_s=3.0,
            description=f"{what} became refused with {expected}",
        )
        return code, seen.get("message")

    def _wait_creds_active(creds):
        # GetCallerIdentity needs no permissions, so it is a safe liveness probe for a session
        # whose permissions are deliberately narrow.
        probe = _client_with_credentials("sts", creds)
        _poll(
            lambda: _error_code(lambda: probe.get_caller_identity()),
            lambda c: c == _OK, timeout_s=120.0, interval_s=2.0,
            description="temporary credentials became active",
        )

    identity_cache = {}

    def _identity():
        if not identity_cache:
            identity_cache.update(sts.get_caller_identity())
        return identity_cache

    def _account_id():
        return _identity()["Account"]

    def _caller_principal_arn():
        """The caller's aws:PrincipalArn: for an assumed-role session, the ROLE arn."""
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

    def _try_assume(client, role_arn, session_name, **kw):
        """The AssumeRole response dict on success, or the error code string on failure (so a
        code result also proves no credentials were issued)."""
        try:
            return client.assume_role(
                RoleArn=role_arn, RoleSessionName=session_name, **kw
            )
        except ClientError as exc:
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
        # A just-tightened trust policy also takes seconds to start refusing.
        return _poll(
            lambda: _try_assume(client, role_arn, session_name, **kw),
            lambda r: r == expected,
            timeout_s=180.0, interval_s=3.0,
            description=f"AssumeRole on {role_arn} began returning {expected}",
        )

    def _sess():
        return ctx.unique_name("sim2real-behav-sess-")

    iam = _make_client_for("iam")

    tag_key = "sim2real-env"
    role_name, role_arn, _role_id = _create_role(
        iam,
        trust_policy=_trust_root(actions=["sts:AssumeRole", "sts:TagSession"]),
        inline_policy=_allow(["s3:ListAllMyBuckets"]),
    )

    # The session policy allows the action ONLY when the principal tag matches. The role's own
    # policy allows it unconditionally, so every outcome below is decided by the condition.
    conditional = _allow(
        ["s3:ListAllMyBuckets"],
        condition={"StringEquals": {f"aws:PrincipalTag/{tag_key}": "allowed"}},
    )

    def _session_with_tags(tags_kv):
        kw = {"Policy": json.dumps(conditional)}
        if tags_kv is not None:
            kw["Tags"] = tags_kv
        resp = _poll(
            lambda: _try_assume(sts, role_arn, _sess(), **kw),
            lambda r: isinstance(r, dict), timeout_s=180.0, interval_s=3.0,
            description="AssumeRole with a session policy + session tags succeeded",
        )
        _wait_creds_active(resp["Credentials"])
        return _client_with_credentials("s3", resp["Credentials"]), resp["AssumedRoleUser"]["Arn"]

    # Positive control: the tag is present and matches.
    matched, _matched_arn = _session_with_tags([{"Key": tag_key, "Value": "allowed"}])
    _poll_allowed(
        lambda: matched.list_buckets(),
        what=f"s3:ListAllMyBuckets with aws:PrincipalTag/{tag_key}=allowed",
    )

    # Only the tag value differs.
    mismatched, mismatched_arn = _session_with_tags([{"Key": tag_key, "Value": "blocked"}])
    code_mismatch, message_mismatch = _poll_denied(
        lambda: mismatched.list_buckets(), "AccessDenied",
        what=f"s3:ListAllMyBuckets with aws:PrincipalTag/{tag_key}=blocked",
    )
    assert code_mismatch == "AccessDenied", (
        "a session tag whose value fails the session policy's StringEquals condition must deny; "
        f"got {code_mismatch!r}"
    )
    assert message_mismatch == (
        f"User: {mismatched_arn} is not authorized to perform: s3:ListAllMyBuckets because no session "
        "policy allows the s3:ListAllMyBuckets action"
    ), message_mismatch

    # An absent condition key must not satisfy StringEquals.
    untagged, untagged_arn = _session_with_tags(None)
    code_absent, message_absent = _poll_denied(
        lambda: untagged.list_buckets(), "AccessDenied",
        what=f"s3:ListAllMyBuckets with aws:PrincipalTag/{tag_key} absent",
    )
    assert code_absent == "AccessDenied", (
        "an absent aws:PrincipalTag must not satisfy a StringEquals condition; got "
        f"{code_absent!r}"
    )
    assert message_absent == (
        f"User: {untagged_arn} is not authorized to perform: s3:ListAllMyBuckets because no session "
        "policy allows the s3:ListAllMyBuckets action"
    ), message_absent

    # The matched session is unaffected by the two denied sessions.
    _poll_allowed(lambda: matched.list_buckets(), what="matched-tag session (still)")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
