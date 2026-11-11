"""assume-role-session-policy-intersection-allows-and-denies."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-session-policy-intersection-allows-and-denies"
GROUP = 'overly-permissive'
SERVICES = ['sts']
# What an error-code helper returns when the call succeeds: equal to no AWS error code.
_OK = "(no error: the call succeeded)"

@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An AssumeRole session's permissions are the intersection of role and session policy: with the
    role allowing two actions and the session policy one, the shared action succeeds and the other
    is denied with AccessDenied and the exact "no session policy allows" message."""

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
        """Poll until fn() fails with exactly `expected`; called only after a positive control
        proved the credential live and the policy propagated, so a deadline miss is the verdict."""
        return _poll(
            lambda: _error_code(fn), lambda c: c == expected,
            timeout_s=timeout_s, interval_s=3.0,
            description=f"{what} became refused with {expected}",
        )

    def _wait_creds_active(creds):
        # GetCallerIdentity needs no permissions, so it is the one safe liveness probe for a
        # deliberately narrow session; it absorbs credential propagation delay on real AWS.
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

    # Two read-only actions in different services so the decision is unambiguous.
    role_name, role_arn, _role_id = _create_role(
        iam, trust_policy=_trust_root(),
        inline_policy=_allow(["s3:ListAllMyBuckets", "iam:ListRoles"]),
    )

    # Positive control with no session policy: proves trust and identity policy propagated.
    control_sess = _sess()
    base = _wait_assumable(sts, role_arn, control_sess)
    _wait_creds_active(base["Credentials"])
    base_s3 = _client_with_credentials("s3", base["Credentials"])
    base_iam = _client_with_credentials("iam", base["Credentials"])
    _poll_allowed(lambda: base_s3.list_buckets(), what="unscoped session s3:ListAllMyBuckets")
    _poll_allowed(lambda: base_iam.list_roles(), what="unscoped session iam:ListRoles")

    scoped_sess = _sess()
    scoped = sts.assume_role(
        RoleArn=role_arn, RoleSessionName=scoped_sess,
        Policy=json.dumps(_allow(["s3:ListAllMyBuckets"])),
    )
    assert scoped["AssumedRoleUser"]["Arn"].endswith(
        f":assumed-role/{role_name}/{scoped_sess}"
    ), (
        "the scoped session must be the SAME role as the control session; got "
        f"{scoped['AssumedRoleUser']['Arn']}"
    )
    _wait_creds_active(scoped["Credentials"])
    scoped_s3 = _client_with_credentials("s3", scoped["Credentials"])
    scoped_iam = _client_with_credentials("iam", scoped["Credentials"])

    # (a) the intersection must KEEP the action both policies allow.
    _poll_allowed(
        lambda: scoped_s3.list_buckets(),
        what="s3:ListAllMyBuckets allowed by BOTH the role policy and the session policy",
    )

    # (b) the intersection must DROP the action only the role policy allows.
    denied = _poll_denied(
        lambda: scoped_iam.list_roles(), "AccessDenied",
        what="iam:ListRoles allowed by the role policy but NOT by the session policy",
    )
    assert denied == "AccessDenied", (
        "a session policy must NARROW the role's permissions, never leave them intact: "
        f"iam:ListRoles returned {denied!r} instead of AccessDenied"
    )
    try:
        scoped_iam.list_roles()
    except ClientError as exc:
        message = exc.response["Error"].get("Message")
    else:
        raise AssertionError("iam:ListRoles succeeded for the scoped session after it was refused")
    expected = (
        f"User: {scoped['AssumedRoleUser']['Arn']} is not authorized to perform: iam:ListRoles on "
        f"resource: arn:aws:iam::{_account_id()}:role/ because no session policy allows the "
        "iam:ListRoles action"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # (c) the narrowing is scoped to the one session, not to the role.
    _poll_allowed(lambda: base_iam.list_roles(), what="control session iam:ListRoles (still)")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
