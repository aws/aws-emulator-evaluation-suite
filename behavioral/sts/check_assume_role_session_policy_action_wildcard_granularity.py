"""assume-role-session-policy-action-wildcard-granularity."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-session-policy-action-wildcard-granularity"
GROUP = 'overly-permissive'
SERVICES = ['sts']
# What an error-code helper returns when the call succeeds: equal to no AWS error code.
_OK = "(no error: the call succeeded)"

@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A session policy's Action is matched at exactly the granularity written: iam:ListRoles
    grants only itself, iam:ListR* only the matching prefix, and iam:List* both; a too-generous
    or too-strict matcher is caught on the real request path."""

    sts = ctx.client("sts")

    # Minted credentials go only to ctx.client(creds=...), never os.environ: env credentials
    # would shadow the container credential provider for every later check in the process.

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
        """Bounded poll to a condition. Raises on deadline miss -- never a bare sleep."""
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

    # Codes that mean "this freshly minted credential is not globally active yet", NOT a policy
    # decision. Polling past them is what keeps the policy assertions honest.

    def _poll_allowed(fn, *, timeout_s=120.0, what="call"):
        """Poll until fn() succeeds. Used for POSITIVE controls, where a transient
        InvalidClientTokenId or an unpropagated identity policy must not be read as a denial."""
        return _poll(
            lambda: _error_code(fn), lambda c: c == _OK,
            timeout_s=timeout_s, interval_s=3.0,
            description=f"{what} became permitted",
        )

    def _poll_denied(fn, expected, *, timeout_s=60.0, what="call"):
        """Poll until fn() fails with exactly `expected`, returning (code, message); called only
        after a positive control proved the credential live and the policy propagated."""
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
        # GetCallerIdentity requires no permissions at all, so it is the one safe liveness
        # probe for a session whose permissions are deliberately narrow.
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
        """Create a role with teardown registered at creation; return (name, arn, id)."""
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
        """Returns the AssumeRole response dict on success, or the error CODE string on
        failure -- so `result == "AccessDenied"` simultaneously proves the specific code AND
        that no credentials were issued."""
        try:
            return client.assume_role(
                RoleArn=role_arn, RoleSessionName=session_name, **kw
            )
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")

    def _wait_assumable(client, role_arn, session_name, **kw):
        # Trust-policy propagation lags seconds after create/update; a negative asserted before
        # this positive control could pass only because propagation had not completed.
        return _poll(
            lambda: _try_assume(client, role_arn, session_name, **kw),
            lambda r: isinstance(r, dict),
            timeout_s=180.0, interval_s=3.0,
            description=f"role {role_arn} became assumable",
        )

    def _wait_assume_code(client, role_arn, session_name, expected, **kw):
        # The inverse, for a trust policy we just TIGHTENED: the refusal also takes seconds to
        # take effect, so poll until it appears instead of sleeping a fixed interval.
        return _poll(
            lambda: _try_assume(client, role_arn, session_name, **kw),
            lambda r: r == expected,
            timeout_s=180.0, interval_s=3.0,
            description=f"AssumeRole on {role_arn} began returning {expected}",
        )

    def _sess():
        return ctx.unique_name("sim2real-behav-sess-")


    iam = _make_client_for("iam")

    role_name, role_arn, _role_id = _create_role(
        iam, trust_policy=_trust_root(), inline_policy=_allow(["iam:List*"]),
    )

    def _scoped(actions):
        resp = _poll(
            lambda: _try_assume(
                sts, role_arn, _sess(), Policy=json.dumps(_allow(actions)),
            ),
            lambda r: isinstance(r, dict), timeout_s=180.0, interval_s=3.0,
            description=f"AssumeRole with session policy Action={actions} succeeded",
        )
        _wait_creds_active(resp["Credentials"])
        return _client_with_credentials("iam", resp["Credentials"]), resp["AssumedRoleUser"]["Arn"]

    # --- POSITIVE CONTROL: no session policy. The role's iam:List* grant covers both calls, so
    # both must succeed; anything denied below is therefore the session policy's doing.
    base = _wait_assumable(sts, role_arn, _sess())
    _wait_creds_active(base["Credentials"])
    base_iam = _client_with_credentials("iam", base["Credentials"])
    _poll_allowed(lambda: base_iam.list_roles(), what="unscoped session iam:ListRoles")
    _poll_allowed(lambda: base_iam.list_users(), what="unscoped session iam:ListUsers")

    # (a) exact action: must not be matched as a prefix.
    exact, exact_arn = _scoped(["iam:ListRoles"])
    _poll_allowed(lambda: exact.list_roles(), what="Action='iam:ListRoles' -> iam:ListRoles")
    code_exact, message_exact = _poll_denied(
        lambda: exact.list_users(), "AccessDenied",
        what="Action='iam:ListRoles' -> iam:ListUsers",
    )
    assert code_exact == "AccessDenied", (
        "an exact Action must not be matched as a prefix: a session policy granting only "
        f"iam:ListRoles allowed iam:ListUsers (got {code_exact!r})"
    )
    assert message_exact == (
        f"User: {exact_arn} is not authorized to perform: iam:ListUsers on resource: "
        f"arn:aws:iam::{_account_id()}:user/ because no session policy allows the iam:ListUsers action"
    ), message_exact

    # (b) prefix wildcard: must not be widened to the whole service.
    prefix, prefix_arn = _scoped(["iam:ListR*"])
    _poll_allowed(lambda: prefix.list_roles(), what="Action='iam:ListR*' -> iam:ListRoles")
    code_prefix, message_prefix = _poll_denied(
        lambda: prefix.list_users(), "AccessDenied",
        what="Action='iam:ListR*' -> iam:ListUsers",
    )
    assert code_prefix == "AccessDenied", (
        "a prefix wildcard must not be widened to the service: a session policy granting only "
        f"iam:ListR* allowed iam:ListUsers (got {code_prefix!r})"
    )
    assert message_prefix == (
        f"User: {prefix_arn} is not authorized to perform: iam:ListUsers on resource: "
        f"arn:aws:iam::{_account_id()}:user/ because no session policy allows the iam:ListUsers action"
    ), message_prefix

    # (c) proves the matcher does not just deny every wildcard, which would pass (a) and (b).
    broad, _broad_arn = _scoped(["iam:List*"])
    _poll_allowed(lambda: broad.list_roles(), what="Action='iam:List*' -> iam:ListRoles")
    _poll_allowed(lambda: broad.list_users(), what="Action='iam:List*' -> iam:ListUsers")

    _poll_allowed(
        lambda: base_iam.list_users(),
        what=f"unscoped control session on {role_name} (still)",
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
