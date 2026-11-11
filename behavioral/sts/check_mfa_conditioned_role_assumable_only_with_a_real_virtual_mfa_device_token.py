"""mfa-conditioned-role-assumable-only-with-a-real-virtual-mfa-device-token."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import struct
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "mfa-conditioned-role-assumable-only-with-a-real-virtual-mfa-device-token"
GROUP = 'overly-permissive'
SERVICES = ['sts']

# What _outcome returns for a call that succeeded: an object no error code can equal.
_SUCCEEDED = object()

_TOTP_STEP = 30
_TOTP_DIGITS = 6


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """An MFA session from an enrolled virtual device can assume a role requiring
    aws:MultiFactorAuthPresent and read its object; the same user's long-term key cannot.

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_configure-api-require.html
    """

    sts = ctx.client("sts")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    # Minted credentials are never written to os.environ and never appear in an assertion message.
    def _client_with_credentials(service, creds, region=None):
        return ctx.client(service, region=region, creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds.get("SessionToken"),
        })

    def _outcome(fn):
        """The error CODE of a failing call, or _SUCCEEDED -- an object no code can equal -- if
        it succeeded. Polls wait on it in both directions."""
        try:
            fn()
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")
        return _SUCCEEDED

    def _error_code(fn):
        """The error CODE of a call that must be refused; raises when it SUCCEEDS."""
        got = _outcome(fn)
        if got is _SUCCEEDED:
            raise AssertionError("expected the call to be refused, but it SUCCEEDED")
        return got

    def _poll(probe, predicate, *, timeout_s, interval_s=3.0, description="condition",
              teardown=False):
        """Bounded poll to a condition. Raises on deadline miss -- never a bare sleep. A body poll
        is capped by the runner's remaining time; a teardown poll keeps its full timeout."""
        if not teardown:
            timeout_s = _budget_s(ctx, timeout_s)
        deadline = time.monotonic() + timeout_s
        while True:
            last = probe()
            if predicate(last):
                return last
            if time.monotonic() >= deadline:
                if not teardown and _budget_spent(ctx):
                    raise TimeoutError(f"{description}: the run budget ended first; not graded")
                raise AssertionError(
                    f"{description} not reached within {timeout_s}s (last observed: {last!r})")
            time.sleep(interval_s)

    def _poll_allowed(fn, *, timeout_s=240.0, what="call"):
        """Poll until fn() SUCCEEDS. IAM/STS propagation is per-replica: a replica that already
        holds a new key can still lack its policy, so a single-shot success assertion after
        polling past InvalidClientTokenId is racy -- it can pass and then transiently 403. Polling
        on the exact expected success is the only barrier that is not."""
        return _poll(lambda: _outcome(fn), lambda c: c is _SUCCEEDED,
                     timeout_s=timeout_s, interval_s=3.0,
                     description=f"{what} became permitted")

    def _poll_denied(fn, expected, *, timeout_s=180.0, what="call"):
        """Poll until fn() fails with EXACTLY `expected`; returns the refusal's (code, message). Only ever called after a positive
        control on the same session has proven the credential live, so a permissive
        implementation simply never reaches the condition and the deadline miss IS the verdict."""
        def probe():
            try:
                fn()
            except ClientError as exc:
                err = exc.response.get("Error", {})
                return err.get("Code"), err.get("Message")
            return _SUCCEEDED

        return _poll(probe, lambda r: r is not _SUCCEEDED and r[0] == expected,
                     timeout_s=timeout_s, interval_s=3.0,
                     description=f"{what} became refused with {expected}")

    def _wait_creds_active(creds):
        # GetCallerIdentity needs no permissions, so it is the one safe liveness probe for a
        # session whose permissions are deliberately narrow.
        probe = _client_with_credentials("sts", creds)
        _poll(lambda: _outcome(lambda: probe.get_caller_identity()), lambda c: c is _SUCCEEDED,
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
        _poll(lambda: _outcome(lambda: iam.get_role(RoleName=role_name)),
              lambda c: c == "NoSuchEntity", timeout_s=90.0, interval_s=2.0,
              description=f"role {role_name} disappeared", teardown=True)

    def _drop_role_if_present(role_name):
        """As _drop_role, but a no-op if the role is already gone -- for a check that deletes the
        role itself as part of its subject. Never a bare `lambda: None`: it really does delete."""
        if _outcome(lambda: iam.get_role(RoleName=role_name)) == "NoSuchEntity":
            return
        _drop_role(role_name)

    def _try_create_role(role_name, trust_policy, scenario):
        """create_role, returning the Role dict or the error CODE. IAM is eventually consistent
        about a role ARN's usability as a trust-policy PRINCIPAL: MalformedPolicyDocument /
        "Invalid principal in policy" for a role that demonstrably exists, measured on this
        account. It is also eventually consistent about a just-deleted name becoming free."""
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
        _poll(lambda: _outcome(lambda: c.head_bucket(Bucket=bucket)),
              lambda code: code in {"404", "NoSuchBucket"}, timeout_s=90.0, interval_s=2.0,
              description=f"bucket {bucket} disappeared", teardown=True)

    def _new_bucket(scenario, client=None, region=None):
        c = client or s3
        bucket = ctx.unique_name("sim2real-behav-sts-")
        params = {"Bucket": bucket}
        target_region = region or ctx.region
        if target_region and target_region != "us-east-1":
            params["CreateBucketConfiguration"] = {"LocationConstraint": target_region}
        c.create_bucket(**params)
        ctx.on_cleanup(lambda: _drop_bucket(bucket, c))
        c.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _tags_kv(scenario)})
        return bucket

    def _try_assume_refusal(client, role_arn, **kw):
        """The AssumeRole response on success, or the refusal's (code, message)."""
        try:
            return client.assume_role(
                RoleArn=role_arn, RoleSessionName=ctx.unique_name("sim2real-behav-sess-"), **kw)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")

    def _try_assume(client, role_arn, **kw):
        """The AssumeRole response on success, or the error CODE string on failure -- so
        `result == "AccessDenied"` proves the code AND that no credentials were issued."""
        try:
            return client.assume_role(
                RoleArn=role_arn, RoleSessionName=ctx.unique_name("sim2real-behav-sess-"), **kw)
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")

    def _wait_assumable(client, role_arn, **kw):
        # Trust-policy propagation is real: the first AssumeRole against a new role fails for
        # seconds. Establishing this positive control BEFORE any negative assertion is what keeps
        # a still-propagating grant from being read as a refusal.
        return _poll(lambda: _try_assume(client, role_arn, **kw), lambda r: isinstance(r, dict),
                     timeout_s=240.0, interval_s=3.0,
                     description=f"role {role_arn} became assumable")

    def _totp(seed_b32, at_epoch):
        """RFC 6238 TOTP, SHA-1, 30 s step, 6 digits -- what a virtual MFA device computes."""
        secret = base64.b32decode(seed_b32, casefold=True)
        counter = struct.pack(">Q", int(at_epoch) // _TOTP_STEP)
        digest = hmac.new(secret, counter, hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        truncated = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
        return str(truncated % (10 ** _TOTP_DIGITS)).zfill(_TOTP_DIGITS)

    scenario = "sts-mfa-conditioned-assume"
    bucket = _new_bucket(scenario)
    payload = b"mfa-gated"
    key = "mfa-conditioned-object"
    s3.put_object(Bucket=bucket, Key=key, Body=payload)
    objects_arn = f"arn:aws:s3:::{bucket}/*"

    # An IAM user with long-term keys is required: GetSessionToken cannot be called from a role
    # session.
    user_name = ctx.unique_name("sim2real-behav-sts-user-")
    iam.create_user(UserName=user_name, Tags=_tags_kv(scenario))

    def _drop_user():
        # LIFO cleanup runs this after the MFA cleanup registered below, but the ordering is
        # re-asserted here so the teardown is correct even if a leg never got that far.
        for page in iam.get_paginator("list_mfa_devices").paginate(UserName=user_name):
            for dev in page.get("MFADevices", []):
                iam.deactivate_mfa_device(UserName=user_name, SerialNumber=dev["SerialNumber"])
        for page in iam.get_paginator("list_access_keys").paginate(UserName=user_name):
            for k in page.get("AccessKeyMetadata", []):
                iam.delete_access_key(UserName=user_name, AccessKeyId=k["AccessKeyId"])
        for page in iam.get_paginator("list_user_policies").paginate(UserName=user_name):
            for pname in page.get("PolicyNames", []):
                iam.delete_user_policy(UserName=user_name, PolicyName=pname)
        for page in iam.get_paginator("list_attached_user_policies").paginate(UserName=user_name):
            for pol in page.get("AttachedPolicies", []):
                iam.detach_user_policy(UserName=user_name, PolicyArn=pol["PolicyArn"])
        iam.delete_user(UserName=user_name)
        _poll(lambda: _outcome(lambda: iam.get_user(UserName=user_name)),
              lambda c: c == "NoSuchEntity", timeout_s=90.0, interval_s=2.0,
              description=f"user {user_name} disappeared", teardown=True)

    ctx.on_cleanup(_drop_user)
    user_arn = iam.get_user(UserName=user_name)["User"]["Arn"]

    access_key = iam.create_access_key(UserName=user_name)["AccessKey"]
    user_creds = {"AccessKeyId": access_key["AccessKeyId"],
                  "SecretAccessKey": access_key["SecretAccessKey"]}
    ctx.on_cleanup(lambda: iam.delete_access_key(
        UserName=user_name, AccessKeyId=access_key["AccessKeyId"]))

    # --- The MFA-conditioned role. It trusts the user, and only with MFA present.
    role_name = ctx.unique_name("sim2real-behav-sts-role-")
    role_trust = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": user_arn}, "Action": ["sts:AssumeRole"],
         "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}]}
    role = _poll(lambda: _try_create_role(role_name, role_trust, scenario),
                 lambda r: isinstance(r, dict), timeout_s=180.0, interval_s=3.0,
                 description=f"role {role_name} accepted the new user as a principal")
    ctx.on_cleanup(lambda: _drop_role(role_name))
    role_arn = role["Arn"]
    iam.put_role_policy(RoleName=role_name, PolicyName="sim2real-behav-inline",
                        PolicyDocument=json.dumps(_allow(["s3:GetObject"], objects_arn)))

    # The user may assume the role and may use its own MFA device. Without the first it could never
    # reach the trust policy at all, and the negative leg would be about the wrong thing.
    iam.put_user_policy(
        UserName=user_name, PolicyName="sim2real-behav-inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["sts:AssumeRole"], "Resource": role_arn},
            {"Effect": "Allow", "Action": ["iam:GetUser", "iam:ListMFADevices"],
             "Resource": user_arn}]}))

    # --- The user's long-term key must become usable before either leg means anything.
    _wait_creds_active(user_creds)
    user_sts = _client_with_credentials("sts", user_creds)
    user_ident = user_sts.get_caller_identity()
    assert user_ident["Arn"] == user_arn, (
        f"the long-term key does not belong to the user under test: {user_ident['Arn']!r} != "
        f"{user_arn!r}")

    # --- NEGATIVE half: the same user, the same permission, NO MFA. A bounded poll on the exact
    # refusal, after a positive control (GetCallerIdentity above) has proven the key live.
    no_mfa_code, no_mfa_message = _poll(
        lambda: _try_assume_refusal(user_sts, role_arn), lambda r: isinstance(r, tuple),
        timeout_s=240.0, interval_s=3.0,
        description="AssumeRole without MFA became refused")
    assert no_mfa_code == "AccessDenied", (
        "a session with no MFA must not satisfy aws:MultiFactorAuthPresent even though the user is a "
        f"permitted principal and its identity policy allows sts:AssumeRole; got {no_mfa_code!r}")
    expected_no_mfa_message = (
        f"User: {user_arn} is not authorized to perform: sts:AssumeRole on resource: {role_arn}")
    assert no_mfa_message == expected_no_mfa_message, (
        f"expected the refusal message {expected_no_mfa_message!r}, got {no_mfa_message!r}")

    # --- A real virtual MFA device, enrolled with two consecutive codes computed from the seed AWS
    # just generated.
    device = iam.create_virtual_mfa_device(
        VirtualMFADeviceName=ctx.unique_name("sim2real-behav-sts-mfa-"), Tags=_tags_kv(scenario))
    mfa_arn = device["VirtualMFADevice"]["SerialNumber"]
    seed = device["VirtualMFADevice"]["Base32StringSeed"].decode() \
        if isinstance(device["VirtualMFADevice"]["Base32StringSeed"], bytes) \
        else device["VirtualMFADevice"]["Base32StringSeed"]

    def _drop_mfa():
        # Deactivate first: an ENABLED device cannot be deleted, and a user with an enabled device
        # cannot be deleted either.
        # Any refusal here (already deactivated, never enrolled) leaves the delete below to judge.
        _outcome(lambda: iam.deactivate_mfa_device(UserName=user_name, SerialNumber=mfa_arn))
        iam.delete_virtual_mfa_device(SerialNumber=mfa_arn)

    ctx.on_cleanup(_drop_mfa)

    now = time.time()
    first = _totp(seed, now)
    second = _totp(seed, now + _TOTP_STEP)
    assert first != second, (
        "the two enrolment codes must differ, or the TOTP implementation is wrong and an enrolment "
        f"would succeed by luck; both windows produced {first!r}")

    enrol_codes = set()
    refused_codes = set()

    def _wait_for_window_headroom(min_left_s=5.0):
        # A code computed this close to a window boundary can expire before IAM checks it.
        deadline = time.monotonic() + min_left_s + 2.0
        while (_TOTP_STEP - (time.time() % _TOTP_STEP) < min_left_s
               and time.monotonic() < deadline):
            time.sleep(1.0)

    def _enrol():
        """Submit codes for two CONSECUTIVE windows, the previous and the current one, early
        in the current window; retried across windows because a stale pair is refused."""
        _wait_for_window_headroom()
        base = time.time()
        code1 = _totp(seed, base - _TOTP_STEP)
        code2 = _totp(seed, base)
        if code1 == code2:
            return "SameWindow"
        if code2 in enrol_codes:
            return "CodeUsed"
        enrol_codes.update((code1, code2))
        return _outcome(lambda: iam.enable_mfa_device(
            UserName=user_name, SerialNumber=mfa_arn,
            AuthenticationCode1=code1, AuthenticationCode2=code2))

    enrol_result = _poll(_enrol, lambda c: c is _SUCCEEDED, timeout_s=240.0, interval_s=1.0,
                         description="the virtual MFA device was enrolled with two live TOTP codes")
    assert enrol_result is _SUCCEEDED, (
        f"the MFA device could not be enrolled with codes computed from its own seed: {enrol_result!r}")

    enrolled = []
    for page in iam.get_paginator("list_mfa_devices").paginate(UserName=user_name):
        enrolled.extend(d["SerialNumber"] for d in page.get("MFADevices", []))
    assert enrolled == [mfa_arn], (
        "the device must be enrolled against exactly the expected serial; ListMFADevices reports "
        f"{enrolled!r}, expected [{mfa_arn!r}]")

    # --- An MFA-bearing session. The code must be live, so the call is retried across windows rather
    # than being computed once.
    # A refused code is not sent again; the next attempt waits for the next window's code.
    def _get_session_token():
        _wait_for_window_headroom()
        code = _totp(seed, time.time())
        if code in refused_codes:
            return "CodeRefused"
        try:
            return user_sts.get_session_token(
                SerialNumber=mfa_arn, TokenCode=code, DurationSeconds=900)
        except ClientError as exc:
            refused_codes.add(code)
            return exc.response.get("Error", {}).get("Code")

    session = _poll(_get_session_token, lambda r: isinstance(r, dict),
                    timeout_s=240.0, interval_s=1.0,
                    description="GetSessionToken accepted a live TOTP code")
    assert session["Credentials"]["AccessKeyId"].startswith("ASIA"), (
        "an MFA-bearing GetSessionToken must return a temporary key in the ASIA class; got prefix "
        f"{session['Credentials']['AccessKeyId'][:4]!r}")

    # --- POSITIVE half: that session assumes the MFA-conditioned role.
    _wait_creds_active(session["Credentials"])
    mfa_sts = _client_with_credentials("sts", session["Credentials"])
    assumed = _wait_assumable(mfa_sts, role_arn)
    _wait_creds_active(assumed["Credentials"])
    mfa_ident = _client_with_credentials("sts", assumed["Credentials"]).get_caller_identity()
    assert mfa_ident["Arn"].startswith(f"arn:aws:sts::{account}:assumed-role/{role_name}/"), (
        f"the MFA-bearing session did not become role {role_name!r}: {mfa_ident['Arn']!r}")

    # --- and the assumed session does real work: it reads the object it alone is granted.
    mfa_s3 = _client_with_credentials("s3", assumed["Credentials"])
    _poll_allowed(lambda: mfa_s3.get_object(Bucket=bucket, Key=key),
                  what="the MFA-derived assumed-role session reading the object it is granted")
    mfa_read = mfa_s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert mfa_read == payload, (
        "the MFA-bearing session could not read the object its role grants, so the credentials it "
        f"obtained do not work; got {mfa_read!r} instead of {payload!r}")

    # --- EXCLUSIVITY: the user's own long-term key cannot read the object, so the read above proves
    # the MFA-gated role path and not an ambient permission the user already had.
    user_s3 = _client_with_credentials("s3", user_creds)
    user_read_code, user_read_message = _poll_denied(lambda: user_s3.get_object(Bucket=bucket, Key=key), "AccessDenied",
                                  what="the user's own long-term key attempting the identical read")
    assert user_read_code == "AccessDenied", (
        "the IAM user itself carries no s3 permission, so the identical read must be refused -- "
        f"otherwise the MFA session's read proves nothing about the role; got {user_read_code!r}")
    expected_user_read_message = (
        f'User: {user_arn} is not authorized to perform: s3:GetObject on resource: '
        f'"arn:aws:s3:::{bucket}/{key}" because no identity-based policy allows the '
        "s3:GetObject action")
    assert user_read_message == expected_user_read_message, (
        f"expected the refusal message {expected_user_read_message!r}, got {user_read_message!r}")

    # --- EFFECT SCOPING: the object is intact and readable by its owner.
    runner_read = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert runner_read == payload, (
        f"the object itself became unreadable to its owner, so nothing was proven; got {runner_read!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
