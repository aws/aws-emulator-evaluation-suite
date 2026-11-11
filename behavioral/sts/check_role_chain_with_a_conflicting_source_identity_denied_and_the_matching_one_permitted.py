"""role-chain-with-a-conflicting-source-identity-denied-and-the-matching-one-permitted."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "role-chain-with-a-conflicting-source-identity-denied-and-the-matching-one-permitted"
GROUP = 'overly-permissive'
SERVICES = ['sts']

_MATCHING_IDENTITY = "sim2real-alice"
_CONFLICTING_IDENTITY = "sim2real-bob"
# What _error_code returns when the call succeeds: equal to no AWS error code.
_SUCCEEDED = "<call succeeded>"


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """SourceIdentity carries over a role chain and satisfies the next role's sts:SourceIdentity
    trust condition; changing it mid-chain is a ValidationError, a different value is AccessDenied,
    and chained sessions are capped at one hour.

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_monitor.html
    """

    sts = ctx.client("sts")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    # Minted credentials never go to os.environ or into an assertion message.

    def _client_with_credentials(service, creds, region=None):
        return ctx.client(
            service,
            region=region,
            creds={
                "aws_access_key_id": creds["AccessKeyId"],
                "aws_secret_access_key": creds["SecretAccessKey"],
                "aws_session_token": creds.get("SessionToken"),
            },
        )

    def _error_code(fn):
        """The error CODE of a failing call, or ``_SUCCEEDED`` (equal to no AWS code) if it
        succeeded, so an unexpected success never compares equal to an expected code."""
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
                    f"{description} not reached within {timeout_s}s (last observed: {last!r})")
            time.sleep(interval_s)

    def _poll_allowed(fn, *, timeout_s=240.0, what="call"):
        """Poll until fn() SUCCEEDS. IAM/STS propagation is per-replica, so a replica can know a
        new key but not yet its policy; only polling on the expected success is a safe barrier."""
        return _poll(lambda: _error_code(fn), lambda c: c == _SUCCEEDED,
                     timeout_s=timeout_s, interval_s=3.0,
                     description=f"{what} became permitted")

    def _poll_denied(fn, expected, *, timeout_s=180.0, what="call"):
        """Poll until fn() fails with EXACTLY `expected`, returning (code, message). Only ever
        called after a positive control on the same session has proven the credential live, so a
        permissive implementation simply never reaches the condition and the deadline miss IS the verdict."""
        seen = {}

        def _probe():
            try:
                fn()
            except ClientError as exc:
                seen["message"] = exc.response.get("Error", {}).get("Message")
                return exc.response.get("Error", {}).get("Code")
            return _SUCCEEDED

        code = _poll(_probe, lambda c: c == expected,
                     timeout_s=timeout_s, interval_s=3.0,
                     description=f"{what} became refused with {expected}")
        return code, seen.get("message")

    def _wait_creds_active(creds):
        # GetCallerIdentity needs no permissions, so it is the one safe liveness probe for a
        # session whose permissions are deliberately narrow.
        probe = _client_with_credentials("sts", creds)
        _poll(lambda: _error_code(lambda: probe.get_caller_identity()), lambda c: c == _SUCCEEDED,
              timeout_s=180.0, interval_s=2.0,
              description="temporary credentials became active")

    def _tags_kv(scenario):
        return [{"Key": "sim2real:managed", "Value": "true"},
                {"Key": "sim2real", "Value": scenario}]

    account = sts.get_caller_identity()["Account"]

    def _trust_root():
        return {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
             "Action": ["sts:AssumeRole"]}]}

    def _allow(actions, resource="*"):
        return {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": actions, "Resource": resource}]}

    def _drop_role(role_name):
        # Attached managed policies, inline policies AND a permissions boundary all block
        # delete_role, so all three come off first; then poll to actual disappearance.
        for page in iam.get_paginator("list_attached_role_policies").paginate(RoleName=role_name):
            for pol in page.get("AttachedPolicies", []):
                iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
        for page in iam.get_paginator("list_role_policies").paginate(RoleName=role_name):
            for pname in page.get("PolicyNames", []):
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
        if iam.get_role(RoleName=role_name)["Role"].get("PermissionsBoundary"):
            iam.delete_role_permissions_boundary(RoleName=role_name)
        iam.delete_role(RoleName=role_name)
        _poll(lambda: _error_code(lambda: iam.get_role(RoleName=role_name)),
              lambda c: c == "NoSuchEntity", timeout_s=90.0, interval_s=2.0,
              description=f"role {role_name} disappeared")

    def _drop_role_if_present(role_name):
        """As _drop_role, but a no-op if the role is already gone."""
        if _error_code(lambda: iam.get_role(RoleName=role_name)) == "NoSuchEntity":
            return
        _drop_role(role_name)

    def _try_create_role(role_name, trust_policy, scenario):
        """create_role, returning the Role dict or the error CODE. A just-created role ARN can be
        refused as a trust-policy principal ("Invalid principal in policy") until IAM converges."""
        try:
            return iam.create_role(
                RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy),
                MaxSessionDuration=3600, Tags=_tags_kv(scenario))["Role"]
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")

    def _drop_bucket(bucket, client=None):
        c = client or s3
        for page in c.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                c.delete_object(Bucket=bucket, Key=obj["Key"])
        c.delete_bucket(Bucket=bucket)
        _poll(lambda: _error_code(lambda: c.head_bucket(Bucket=bucket)),
              lambda code: code in {"404", "NoSuchBucket"}, timeout_s=90.0, interval_s=2.0,
              description=f"bucket {bucket} disappeared")

    def _new_bucket(scenario, client=None, region=None):
        c = client or s3
        bucket = ctx.unique_name("sim2real-behav-sts-")
        params = {"Bucket": bucket}
        target_region = region or ctx.region
        # CreateBucket in us-east-1 rejects an explicit LocationConstraint; it must be omitted.
        if target_region and target_region != "us-east-1":
            params["CreateBucketConfiguration"] = {"LocationConstraint": target_region}
        c.create_bucket(**params)
        ctx.on_cleanup(lambda: _drop_bucket(bucket, c))
        # Tagged so tag-based cleanup (Resource Groups Tagging API) can find it.
        c.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _tags_kv(scenario)})
        return bucket

    def _try_assume(client, role_arn, seen=None, **kw):
        """The AssumeRole response on success, or the error CODE string on failure -- so
        `result == "AccessDenied"` proves the code AND that no credentials were issued. A
        failure's message goes into ``seen`` when given."""
        try:
            return client.assume_role(
                RoleArn=role_arn, RoleSessionName=ctx.unique_name("sim2real-behav-sess-"), **kw)
        except ClientError as exc:
            if seen is not None:
                seen["message"] = exc.response.get("Error", {}).get("Message")
            return exc.response.get("Error", {}).get("Code")

    def _wait_assumable(client, role_arn, **kw):
        # Trust-policy propagation is real: the first AssumeRole against a new role fails for
        # seconds. Establishing this positive control BEFORE any negative assertion is what keeps
        # a still-propagating grant from being read as a refusal.
        return _poll(lambda: _try_assume(client, role_arn, **kw), lambda r: isinstance(r, dict),
                     timeout_s=240.0, interval_s=3.0,
                     description=f"role {role_arn} became assumable")

    scenario = "sts-source-identity-role-chain"
    bucket = _new_bucket(scenario)
    payload = b"chained"
    key = "source-identity-chain-object"
    s3.put_object(Bucket=bucket, Key=key, Body=payload)
    objects_arn = f"arn:aws:s3:::{bucket}/*"

    # --- Role A: assumable by the account, may assume other roles and may SET a source identity.
    # It deliberately carries NO s3 permission, which is what makes B's read discriminating.
    # Exclusivity uses identity policies, not a bucket Deny, which would also lock out teardown.
    role_a_name = ctx.unique_name("sim2real-behav-sts-role-")
    role_a = iam.create_role(
        RoleName=role_a_name,
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
             "Action": ["sts:AssumeRole", "sts:SetSourceIdentity"]}]}),
        MaxSessionDuration=3600, Tags=_tags_kv(scenario))["Role"]
    ctx.on_cleanup(lambda: _drop_role(role_a_name))
    role_a_arn = role_a["Arn"]
    iam.put_role_policy(RoleName=role_a_name, PolicyName="sim2real-behav-inline",
                        PolicyDocument=json.dumps(
                            _allow(["sts:AssumeRole", "sts:SetSourceIdentity"])))

    # --- Role B: trusts ONLY role A, and only when the caller's sts:SourceIdentity matches.
    role_b_name = ctx.unique_name("sim2real-behav-sts-role-")
    role_b_trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": role_a_arn},
         "Action": ["sts:AssumeRole", "sts:SetSourceIdentity"],
         "Condition": {"StringEquals": {"sts:SourceIdentity": _MATCHING_IDENTITY}}}]}
    role_b = _poll(
        lambda: _try_create_role(role_b_name, role_b_trust, scenario),
        lambda r: isinstance(r, dict), timeout_s=180.0, interval_s=3.0,
        description=f"role {role_b_name} accepted role A as a trust-policy principal")
    ctx.on_cleanup(lambda: _drop_role(role_b_name))
    role_b_arn = role_b["Arn"]
    iam.put_role_policy(RoleName=role_b_name, PolicyName="sim2real-behav-inline",
                        PolicyDocument=json.dumps(_allow(["s3:GetObject"], objects_arn)))

    # --- Hop 1: role A, with the matching source identity.
    a_session = _wait_assumable(sts, role_a_arn, SourceIdentity=_MATCHING_IDENTITY)
    assert a_session.get("SourceIdentity") == _MATCHING_IDENTITY, (
        "AssumeRole must echo the SourceIdentity it recorded on the session; got "
        f"{a_session.get('SourceIdentity')!r}")
    _wait_creds_active(a_session["Credentials"])
    a_sts = _client_with_credentials("sts", a_session["Credentials"])
    a_s3 = _client_with_credentials("s3", a_session["Credentials"])

    # --- Hop 2 and the POSITIVE CONTROL: chain into B passing NO SourceIdentity. The value must
    # carry over from the calling session, or the trust condition could not be satisfied.
    b_session = _wait_assumable(a_sts, role_b_arn)
    assert b_session.get("SourceIdentity") == _MATCHING_IDENTITY, (
        "the SourceIdentity must carry over into the chained session automatically, without being "
        f"passed again; the chained session reports {b_session.get('SourceIdentity')!r}")
    _wait_creds_active(b_session["Credentials"])
    b_sts = _client_with_credentials("sts", b_session["Credentials"])
    b_s3 = _client_with_credentials("s3", b_session["Credentials"])

    a_caller = a_sts.get_caller_identity()
    b_caller = b_sts.get_caller_identity()
    assert b_caller["Arn"].startswith(f"arn:aws:sts::{account}:assumed-role/{role_b_name}/"), (
        f"the chained identity is not role B: {b_caller['Arn']!r}")
    assert a_caller["Arn"] != b_caller["Arn"], (
        "the two hops must be different identities, or nothing was chained: "
        f"{a_caller['Arn']!r} == {b_caller['Arn']!r}")

    # --- The chain is REAL: B reads the object.
    _poll_allowed(lambda: b_s3.get_object(Bucket=bucket, Key=key),
                  what="the chained role-B session reading the object only B is granted")
    b_read = b_s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert b_read == payload, (
        "the chained role-B session could not read the object its identity policy grants, so the "
        f"second hop produced credentials that do not work; got {b_read!r}")

    # --- EXCLUSIVITY: role A, on the identical call, is refused. This is what makes B's read proof
    # of the chain rather than proof that anyone in the account can read the object.
    a_read_code, a_read_message = _poll_denied(lambda: a_s3.get_object(Bucket=bucket, Key=key), "AccessDenied",
                               what="role A attempting the identical read")
    assert a_read_code == "AccessDenied", (
        "role A carries no s3 permission, so the identical read must be refused -- otherwise the "
        f"successful read above does not prove the chain reached role B; got {a_read_code!r}")
    assert a_read_message == (
        f'User: {a_caller["Arn"]} is not authorized to perform: s3:GetObject on resource: '
        f'"arn:aws:s3:::{bucket}/{key}" because no identity-based policy allows the s3:GetObject action'
    ), a_read_message

    # --- EFFECT SCOPING: the object is intact and readable by its owner.
    runner_read = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert runner_read == payload, (
        f"the object itself became unreadable to its owner, so nothing was proven; got {runner_read!r}")

    # --- NEGATIVE 1: the same live A session cannot CHANGE the source identity on the second hop.
    # AWS answers ValidationError ("The source identity is already set ..."), not AccessDenied.
    conflicting_refusal = {}
    conflicting = _try_assume(
        a_sts, role_b_arn, conflicting_refusal, SourceIdentity=_CONFLICTING_IDENTITY
    )
    assert conflicting == "ValidationError", (
        "a chained AssumeRole that presents a DIFFERENT SourceIdentity than the calling session "
        f"already carries must be refused with ValidationError; got {conflicting!r}. A success would "
        "mean a source identity can be laundered mid-chain, which is the whole guarantee")
    assert conflicting_refusal.get("message") == (
        "The source identity is already set for this assume role session"
    ), conflicting_refusal

    # --- NEGATIVE 2: a session whose SourceIdentity is the other value does not satisfy the
    # StringEquals condition, even though role A is a permitted principal.
    a2_session = _wait_assumable(sts, role_a_arn, SourceIdentity=_CONFLICTING_IDENTITY)
    assert a2_session.get("SourceIdentity") == _CONFLICTING_IDENTITY, (
        f"the second A session did not take the other identity: {a2_session.get('SourceIdentity')!r}")
    _wait_creds_active(a2_session["Credentials"])
    a2_sts = _client_with_credentials("sts", a2_session["Credentials"])
    wrong_identity_refusal = {}
    wrong_identity_code = _poll(
        lambda: _try_assume(a2_sts, role_b_arn, wrong_identity_refusal), lambda r: isinstance(r, str),
        timeout_s=180.0, interval_s=3.0,
        description="role B refused a chain carrying the other source identity")
    assert wrong_identity_code == "AccessDenied", (
        f"a session whose SourceIdentity is {_CONFLICTING_IDENTITY!r} must not satisfy a StringEquals "
        f"condition on {_MATCHING_IDENTITY!r}; got {wrong_identity_code!r}. Role A is a permitted "
        "principal of role B, so the only thing distinguishing this call from the successful one is "
        "the source identity")
    assert wrong_identity_refusal.get("message") == (
        f"User: {a2_session['AssumedRoleUser']['Arn']} is not authorized to perform: "
        f"sts:SetSourceIdentity on resource: {role_b_arn}"
    ), wrong_identity_refusal

    # --- The one-hour cap on role chaining, asserted on the same chained session because it is free
    # to claim once the hop exists: a chained AssumeRole cannot request more than 3600 s.
    over_cap_refusal = {}
    chained_over_cap = _try_assume(a_sts, role_b_arn, over_cap_refusal, DurationSeconds=7200)
    assert chained_over_cap == "ValidationError", (
        "a chained AssumeRole must refuse a DurationSeconds above the one-hour role-chaining cap "
        f"with ValidationError; got {chained_over_cap!r}")
    assert over_cap_refusal.get("message") == (
        "The requested DurationSeconds exceeds the MaxSessionDuration set for this role."
    ), over_cap_refusal

    # --- and exactly the cap is accepted, which is what makes the refusal above a CAP rather than a
    # blanket refusal of DurationSeconds on a chained hop.
    at_cap = _try_assume(a_sts, role_b_arn, DurationSeconds=3600)
    assert isinstance(at_cap, dict), (
        "a chained AssumeRole must accept DurationSeconds exactly at the one-hour cap, or the "
        f"refusal above is not a cap; got {at_cap!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
