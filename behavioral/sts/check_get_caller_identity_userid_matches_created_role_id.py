"""get-caller-identity-userid-matches-created-role-id."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-caller-identity-userid-matches-created-role-id"
GROUP = 'credential-issuance'
SERVICES = ['sts']

_SUCCEEDED = "<call succeeded>"


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCallerIdentity in an assumed-role session returns UserId == <RoleId>:<SessionName>
    and Arn == arn:aws:sts::<acct>:assumed-role/<RoleName>/<SessionName>, checked against the
    RoleId that CreateRole actually minted."""

    sts = ctx.client("sts")

    # Minted credentials go only to ctx.client(creds=...), never os.environ, where they
    # would shadow the container credential provider for every later check.

    def _client_with_credentials(service, creds):
        return ctx.client(
            service,
            creds={
                "aws_access_key_id": creds["AccessKeyId"],
                "aws_secret_access_key": creds["SecretAccessKey"],
                "aws_session_token": creds.get("SessionToken"),
            },
        )

    def _error_code(fn):
        """fn()'s error code, or ``_SUCCEEDED`` (a value no error code can equal) on success."""
        try:
            fn()
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")
        return _SUCCEEDED

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

    def _wait_creds_active(creds):
        # GetCallerIdentity requires no permissions, so it is the one safe liveness probe for a
        # session whose permissions are deliberately narrow.
        probe = _client_with_credentials("sts", creds)
        _poll(
            lambda: _error_code(lambda: probe.get_caller_identity()),
            lambda c: c == _SUCCEEDED, timeout_s=120.0, interval_s=2.0,
            description="temporary credentials became active",
        )

    identity_cache = {}

    def _identity():
        if not identity_cache:
            identity_cache.update(sts.get_caller_identity())
        return identity_cache

    def _account_id():
        return _identity()["Account"]

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

    def _drop_role(iam, role_name):
        # Attached and inline policies both block delete_role, so remove them first.
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
        """Create a role, register its teardown at creation, and return (name, arn, id)."""
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
        # Trust-policy propagation makes the first AssumeRole fail for seconds; negatives run
        # only after this positive control so propagation lag cannot pass as a refusal.
        return _poll(
            lambda: _try_assume(client, role_arn, session_name, **kw),
            lambda r: isinstance(r, dict),
            timeout_s=180.0, interval_s=3.0,
            description=f"role {role_arn} became assumable",
        )

    def _sess():
        return ctx.unique_name("sim2real-behav-sess-")


    iam = ctx.client("iam")

    account = _account_id()
    role_name, role_arn, role_id = _create_role(iam, trust_policy=_trust_root())

    assert role_id.startswith("AROA"), (
        f"CreateRole must mint a unique role id in the AROA class; got {role_id!r}"
    )

    session_name = _sess()
    resp = _wait_assumable(sts, role_arn, session_name)

    aru = resp["AssumedRoleUser"]
    expected_arn = f"arn:aws:sts::{account}:assumed-role/{role_name}/{session_name}"
    expected_uid = f"{role_id}:{session_name}"

    assert aru["Arn"] == expected_arn, (
        f"AssumeRole.AssumedRoleUser.Arn must be {expected_arn!r}; got {aru['Arn']!r}"
    )
    assert aru["AssumedRoleId"] == expected_uid, (
        "AssumeRole.AssumedRoleUser.AssumedRoleId must be '<RoleId>:<SessionName>' built from "
        f"the RoleId CreateRole returned, i.e. {expected_uid!r}; got {aru['AssumedRoleId']!r}"
    )

    # Structure only: never assert on the secret access key or session token value.
    creds = resp["Credentials"]
    assert creds["AccessKeyId"].startswith("ASIA"), (
        "a temporary AssumeRole access key id must be in the ASIA class; got prefix "
        f"{creds['AccessKeyId'][:4]!r}"
    )
    assert isinstance(creds.get("SecretAccessKey"), str) and creds["SecretAccessKey"], (
        "AssumeRole must return a non-empty SecretAccessKey (value deliberately not asserted)"
    )
    assert isinstance(creds.get("SessionToken"), str) and creds["SessionToken"], (
        "AssumeRole must return a non-empty SessionToken (value deliberately not asserted)"
    )

    _wait_creds_active(creds)
    derived = _client_with_credentials("sts", creds)

    def _identity_or_code():
        try:
            return derived.get_caller_identity()
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")

    identity = _poll(
        _identity_or_code, lambda r: isinstance(r, dict),
        timeout_s=120.0, interval_s=2.0,
        description="GetCallerIdentity in the assumed-role session returned",
    )

    assert identity["Account"] == account, (identity["Account"], account)
    assert identity["Arn"] == expected_arn, (
        "GetCallerIdentity in an assumed-role session must return the sts assumed-role ARN "
        f"{expected_arn!r}, not the iam role ARN; got {identity['Arn']!r}"
    )
    assert identity["Arn"] != role_arn, (
        "GetCallerIdentity must NOT echo the role's iam ARN back as the caller identity: "
        f"{identity['Arn']!r} == {role_arn!r}"
    )
    assert identity["UserId"] == expected_uid, (
        "GetCallerIdentity.UserId in an assumed-role session must be "
        f"'<RoleId>:<SessionName>' = {expected_uid!r}; got {identity['UserId']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
