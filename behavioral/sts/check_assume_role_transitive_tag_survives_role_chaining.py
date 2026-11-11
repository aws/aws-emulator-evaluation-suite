"""assume-role-transitive-tag-survives-role-chaining."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "assume-role-transitive-tag-survives-role-chaining"
GROUP = 'overly-permissive'
SERVICES = ['sts']
# What an error-code helper returns when the call succeeds: equal to no AWS error code.
_OK = "(no error: the call succeeded)"

# STS caches an ALLOW decision for a (role, calling principal) pair for ~5 minutes: after
# update_assume_role_policy tightens a trust policy, AssumeRole keeps succeeding for ~300s even
# though GetRole already returns the new document. Every poll that waits for a trust-policy
# edit to become observable has to outlast that cache.
_CACHE_DEADLINE_S = 600.0

@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A tag named in TransitiveTagKeys survives role chaining and decides a condition in the
    chained session while a non-transitive tag does not; the chained assume also needs
    sts:TagSession on the target's trust policy.

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html
    """

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
        # deliberately narrow session; fresh credentials can take up to ~120s to become active.
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
        # The inverse, for a trust policy we just tightened: STS keeps serving a cached allow for
        # a role/principal pair for ~5 minutes, so this polls to _CACHE_DEADLINE_S.
        return _poll(
            lambda: _try_assume(client, role_arn, session_name, **kw),
            lambda r: r == expected,
            timeout_s=_CACHE_DEADLINE_S, interval_s=5.0,
            description=f"AssumeRole on {role_arn} began returning {expected}",
        )

    def _sess():
        return ctx.unique_name("sim2real-behav-sess-")


    iam = _make_client_for("iam")

    trans_key, trans_val = "sim2real-trans", "t1"
    plain_key, plain_val = "sim2real-nontrans", "t2"

    # Role B allows the action unconditionally, so outcomes are decided by the session policy's
    # condition on the propagated tag. Its trust policy must also allow sts:TagSession because
    # the chained assume carries transitive tags forward and so is itself a tagging call.
    role_b_name, role_b_arn, _b_id = _create_role(
        iam, trust_policy=_trust_root(actions=["sts:AssumeRole", "sts:TagSession"]),
        inline_policy=_allow(["s3:ListAllMyBuckets"]),
    )
    # Role B_plain differs only in omitting sts:TagSession from its trust policy.
    role_bp_name, role_bp_arn, _bp_id = _create_role(
        iam, trust_policy=_trust_root(actions=["sts:AssumeRole"]),
        inline_policy=_allow(["s3:ListAllMyBuckets"]),
    )
    # Role A may assume both Bs (with tagging) and may itself list buckets (first-hop control).
    role_a_name, role_a_arn, _a_id = _create_role(
        iam,
        trust_policy=_trust_root(actions=["sts:AssumeRole", "sts:TagSession"]),
        inline_policy={
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["s3:ListAllMyBuckets"], "Resource": "*"},
                {
                    "Effect": "Allow",
                    "Action": ["sts:AssumeRole", "sts:TagSession"],
                    "Resource": [role_b_arn, role_bp_arn],
                },
            ],
        },
    )

    # Positive control, hop 1: role A is assumable with both tags.
    first = _poll(
        lambda: _try_assume(
            sts, role_a_arn, _sess(),
            Tags=[
                {"Key": trans_key, "Value": trans_val},
                {"Key": plain_key, "Value": plain_val},
            ],
            TransitiveTagKeys=[trans_key],
        ),
        lambda r: isinstance(r, dict), timeout_s=180.0, interval_s=3.0,
        description="role A became assumable with session tags + TransitiveTagKeys",
    )
    _wait_creds_active(first["Credentials"])
    first_s3 = _client_with_credentials("s3", first["Credentials"])
    _poll_allowed(lambda: first_s3.list_buckets(), what="first-hop session s3:ListAllMyBuckets")

    # Chained AssumeRole is issued BY the first session, never by the ambient caller.
    chain_sts = _client_with_credentials("sts", first["Credentials"])

    def _chained_policy(cond_key, cond_val):
        return json.dumps(_allow(
            ["s3:ListAllMyBuckets"],
            condition={"StringEquals": {f"aws:PrincipalTag/{cond_key}": cond_val}},
        ))

    def _chained_s3(cond_key, cond_val):
        resp = _poll(
            lambda: _try_assume(
                chain_sts, role_b_arn, _sess(),
                Policy=_chained_policy(cond_key, cond_val),
            ),
            lambda r: isinstance(r, dict), timeout_s=180.0, interval_s=3.0,
            description=f"chained AssumeRole into {role_b_name} succeeded",
        )
        _wait_creds_active(resp["Credentials"])
        return _client_with_credentials("s3", resp["Credentials"])

    # The chained assume needs sts:TagSession on the target even though it passes no Tags: the
    # transitive tags are forwarded automatically.
    try:
        chain_sts.assume_role(
            RoleArn=role_bp_arn, RoleSessionName=_sess(),
            Policy=_chained_policy(trans_key, trans_val),
        )
        raise AssertionError(
            f"a chained AssumeRole carrying transitive tags forward must be authorized for "
            f"sts:TagSession on the TARGET role's trust policy; {role_bp_name} trusts only "
            f"sts:AssumeRole, so the chained assume must be refused -- it succeeded instead"
        )
    except ClientError as exc:
        err = exc.response.get("Error", {})
        assert err.get("Code") == "AccessDenied", (
            f"the chained assume into {role_bp_name} must be refused with AccessDenied, got "
            f"{err.get('Code')!r}: {err.get('Message')!r}"
        )
        expected = (
            f"User: {first['AssumedRoleUser']['Arn']} is not authorized to perform: "
            f"sts:TagSession on resource: {role_bp_arn}"
        )
        assert err.get("Message") == expected, (
            f"the refusal must name the implicitly-required action sts:TagSession -- that is what "
            f"identifies the transitive-tag forwarding as the cause rather than the assume "
            f"itself; expected {expected!r}, got {err.get('Message')!r}"
        )

    # Positive control, hop 2: the transitive tag is present in the chained session.
    chained_transitive = _chained_s3(trans_key, trans_val)
    _poll_allowed(
        lambda: chained_transitive.list_buckets(),
        what=f"chained session condition on transitive aws:PrincipalTag/{trans_key}",
    )

    # The non-transitive tag must not have crossed the chain, so its condition cannot match.
    chained_plain = _chained_s3(plain_key, plain_val)
    code = _poll_denied(
        lambda: chained_plain.list_buckets(), "AccessDenied",
        what=f"chained session condition on non-transitive aws:PrincipalTag/{plain_key}",
    )
    assert code == "AccessDenied", (
        f"a session tag NOT listed in TransitiveTagKeys must not survive role chaining into "
        f"{role_b_name}; the chained session satisfied a condition on "
        f"aws:PrincipalTag/{plain_key} and returned {code!r} instead of AccessDenied"
    )

    _poll_allowed(
        lambda: chained_transitive.list_buckets(),
        what=f"chained transitive-tag session from {role_a_name} (still)",
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
