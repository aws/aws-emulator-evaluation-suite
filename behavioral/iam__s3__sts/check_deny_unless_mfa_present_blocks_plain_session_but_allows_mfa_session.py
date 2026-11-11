"""deny-unless-mfa-present-blocks-plain-session-but-allows-mfa-session."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import struct
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deny-unless-mfa-present-blocks-plain-session-but-allows-mfa-session"
GROUP = "overly-permissive"
SERVICES = ["iam", "s3", "sts"]

# What _outcome returns for a call that succeeded: an object no error code can equal.
_SUCCEEDED = object()

_TOTP_STEP = 30
_TOTP_DIGITS = 6

# The bootstrap actions a user must keep even while every other action is denied, or it could
# never enroll its own MFA device or ever obtain an MFA-bearing session -- the standard AWS
# "require MFA" NotAction exemption list.
_BOOTSTRAP_ACTIONS = [
    "iam:GetUser",
    "iam:ListMFADevices",
    "iam:ListVirtualMFADevices",
    "iam:CreateVirtualMFADevice",
    "iam:EnableMFADevice",
    "iam:ResyncMFADevice",
    "sts:GetSessionToken",
]


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
    """A Deny-unless-MFA policy refuses s3:PutObject from the user's plain key with AccessDenied and
    no object created, but permits the same call from a GetSessionToken session with a live TOTP.

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_configure-api-require.html
    """
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    def _client_with_credentials(service, creds, region=None):
        return ctx.client(service, region=region, creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds.get("SessionToken"),
        })

    def _outcome(fn):
        """The error code of a failing call, or _SUCCEEDED if it succeeded."""
        try:
            fn()
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")
        return _SUCCEEDED

    def _poll(probe, predicate, *, timeout_s, interval_s=3.0, description="condition", budgeted=False):
        deadline = time.monotonic() + timeout_s
        while True:
            last = probe()
            if predicate(last):
                return last
            if time.monotonic() >= deadline:
                if budgeted and _budget_spent(ctx):
                    raise TimeoutError(f"{description}: the run budget ended first; not graded")
                raise AssertionError(
                    f"{description} not reached within {timeout_s}s (last observed: {last!r})")
            time.sleep(interval_s)

    def _poll_allowed(fn, *, timeout_s=180.0, what="call"):
        return _poll(lambda: _outcome(fn), lambda c: c is _SUCCEEDED,
                     timeout_s=_budget_s(ctx, timeout_s), interval_s=1.0,
                     description=f"{what} became permitted", budgeted=True)

    def _denial(fn):
        """(code, message) of a failing call, or _SUCCEEDED."""
        try:
            fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        return _SUCCEEDED

    def _poll_denied(fn, expected, *, timeout_s=180.0, what="call"):
        return _poll(lambda: _denial(fn), lambda r: r != _SUCCEEDED and r[0] == expected,
                     timeout_s=_budget_s(ctx, timeout_s), interval_s=1.0,
                     description=f"{what} became refused with {expected}", budgeted=True)

    def _wait_creds_active(creds):
        probe = _client_with_credentials("sts", creds)
        _poll(lambda: _outcome(lambda: probe.get_caller_identity()), lambda c: c is _SUCCEEDED,
              timeout_s=_budget_s(ctx, 180.0), interval_s=1.0,
              description="temporary credentials became active", budgeted=True)

    def _tags_kv(scenario):
        return [{"Key": "sim2real:managed", "Value": "true"},
                {"Key": "sim2real", "Value": scenario}]

    def _totp(seed_b32, at_epoch):
        """RFC 6238 TOTP, SHA-1, 30 s step, 6 digits -- what a virtual MFA device computes."""
        secret = base64.b32decode(seed_b32, casefold=True)
        counter = struct.pack(">Q", int(at_epoch) // _TOTP_STEP)
        digest = hmac.new(secret, counter, hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        truncated = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
        return str(truncated % (10 ** _TOTP_DIGITS)).zfill(_TOTP_DIGITS)

    def _drop_bucket(bucket):
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
        _poll(lambda: _outcome(lambda: s3.head_bucket(Bucket=bucket)),
              lambda code: code in {"404", "NoSuchBucket"}, timeout_s=90.0, interval_s=2.0,
              description=f"bucket {bucket} disappeared")

    def _new_bucket(scenario):
        bucket = ctx.unique_name("sim2real-xsvc-mfa-")
        params = {"Bucket": bucket}
        if ctx.region != "us-east-1":
            params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
        s3.create_bucket(**params)
        ctx.on_cleanup(lambda: _drop_bucket(bucket))
        s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _tags_kv(scenario)})
        return bucket

    scenario = "iam-sts-deny-unless-mfa-present"
    bucket = _new_bucket(scenario)
    plain_key, mfa_key = "deny-unless-mfa/plain-attempt.bin", "deny-unless-mfa/mfa-session.bin"
    payload = b"mfa-gated-s3-write"

    # --- The USER. Long-term keys only (GetSessionToken with MFA cannot be called from an
    # assumed-role session), so an IAM user is required, not a role.
    user_name = ctx.unique_name("sim2real-xsvc-mfa-user-")
    iam.create_user(UserName=user_name, Tags=_tags_kv(scenario))

    def _drop_user():
        for page in iam.get_paginator("list_mfa_devices").paginate(UserName=user_name):
            for dev in page.get("MFADevices", []):
                iam.deactivate_mfa_device(UserName=user_name, SerialNumber=dev["SerialNumber"])
        for page in iam.get_paginator("list_access_keys").paginate(UserName=user_name):
            for k in page.get("AccessKeyMetadata", []):
                iam.delete_access_key(UserName=user_name, AccessKeyId=k["AccessKeyId"])
        for page in iam.get_paginator("list_user_policies").paginate(UserName=user_name):
            for pname in page.get("PolicyNames", []):
                iam.delete_user_policy(UserName=user_name, PolicyName=pname)
        iam.delete_user(UserName=user_name)
        _poll(lambda: _outcome(lambda: iam.get_user(UserName=user_name)),
              lambda c: c == "NoSuchEntity", timeout_s=90.0, interval_s=2.0,
              description=f"user {user_name} disappeared")

    ctx.on_cleanup(_drop_user)
    user_arn = iam.get_user(UserName=user_name)["User"]["Arn"]

    # --- The policy under test: an unconditional Allow for the real call under test, plus an
    # explicit Deny of everything EXCEPT the MFA bootstrap actions, unless MFA is present.
    policy = {"Version": "2012-10-17", "Statement": [
        {"Sid": "BootstrapMFA", "Effect": "Allow", "Action": _BOOTSTRAP_ACTIONS, "Resource": "*"},
        {"Sid": "S3Write", "Effect": "Allow", "Action": ["s3:PutObject", "s3:GetObject"],
         "Resource": f"arn:aws:s3:::{bucket}/*"},
        {"Sid": "DenyUnlessMFA", "Effect": "Deny", "NotAction": _BOOTSTRAP_ACTIONS,
         "Resource": "*",
         "Condition": {"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}}},
    ]}
    iam.put_user_policy(UserName=user_name, PolicyName="sim2real-xsvc-deny-unless-mfa",
                        PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_user_policy(
        UserName=user_name, PolicyName="sim2real-xsvc-deny-unless-mfa"))

    access_key = iam.create_access_key(UserName=user_name)["AccessKey"]
    plain_creds = {"AccessKeyId": access_key["AccessKeyId"],
                   "SecretAccessKey": access_key["SecretAccessKey"]}
    ctx.on_cleanup(lambda: iam.delete_access_key(
        UserName=user_name, AccessKeyId=access_key["AccessKeyId"]))

    _wait_creds_active(plain_creds)
    plain_iam = _client_with_credentials("iam", plain_creds)
    plain_s3 = _client_with_credentials("s3", plain_creds)

    # --- POSITIVE CONTROL: a bootstrap action (exempted from the deny) proves the plain key is
    # live and the policy has propagated, BEFORE the negative assertion means anything.
    got_user = _poll(lambda: _outcome(lambda: plain_iam.get_user(UserName=user_name)),
                     lambda c: c is _SUCCEEDED, timeout_s=_budget_s(ctx, 120.0), interval_s=1.0,
                     description="bootstrap action iam:GetUser became permitted", budgeted=True)
    assert got_user is _SUCCEEDED, "the bootstrap action must succeed before any denial is meaningful"

    # --- NEGATIVE half: the plain session, no MFA, attempts the real call. Exact code and message.
    plain_code, plain_message = _poll_denied(
        lambda: plain_s3.put_object(Bucket=bucket, Key=plain_key, Body=payload), "AccessDenied",
        what="s3:PutObject by the plain (no-MFA) session")
    assert plain_code == "AccessDenied", (
        f"a session with no aws:MultiFactorAuthPresent must be refused the real call by the "
        f"explicit Deny-unless-MFA statement; got {plain_code!r}")
    expected_plain_message = (
        f"User: {user_arn} is not authorized to perform: s3:PutObject on resource: "
        f'"arn:aws:s3:::{bucket}/{plain_key}" with an explicit deny in an identity-based policy')
    assert plain_message == expected_plain_message, (
        f"expected the refusal message {expected_plain_message!r}, got {plain_message!r}")

    # --- EFFECT ABSENT: the denied PutObject left nothing behind.
    plain_head_code = _outcome(lambda: s3.head_object(Bucket=bucket, Key=plain_key))
    assert plain_head_code == "404", (
        f"the denied PutObject must leave no object behind; HeadObject by the owner returned "
        f"{plain_head_code!r} instead of 404")

    # --- A real virtual MFA device, enrolled with two consecutive live TOTP codes computed from
    # the seed AWS just generated for this run.
    device = iam.create_virtual_mfa_device(
        VirtualMFADeviceName=ctx.unique_name("sim2real-xsvc-mfa-dev-"), Tags=_tags_kv(scenario))
    mfa_arn = device["VirtualMFADevice"]["SerialNumber"]
    seed = device["VirtualMFADevice"]["Base32StringSeed"]
    seed = seed.decode() if isinstance(seed, bytes) else seed

    def _drop_mfa():
        _outcome(lambda: iam.deactivate_mfa_device(UserName=user_name, SerialNumber=mfa_arn))
        iam.delete_virtual_mfa_device(SerialNumber=mfa_arn)

    ctx.on_cleanup(_drop_mfa)

    now = time.time()
    first, second = _totp(seed, now), _totp(seed, now + _TOTP_STEP)
    assert first != second, (
        "the two enrolment codes must differ, or the TOTP implementation is wrong and enrolment "
        f"would succeed by luck; both windows produced {first!r}")

    # Enrolment consumes two consecutive windows; GetSessionToken then sends only a later one, so
    # IAM's single-use protection never sees a code twice.
    consumed = {"counter": None}

    def _enrol():
        cur = int(time.time()) // _TOTP_STEP
        result = None
        for base in (cur - 1, cur):
            result = _outcome(lambda: iam.enable_mfa_device(
                UserName=user_name, SerialNumber=mfa_arn,
                AuthenticationCode1=_totp(seed, base * _TOTP_STEP),
                AuthenticationCode2=_totp(seed, (base + 1) * _TOTP_STEP)))
            if result is _SUCCEEDED:
                consumed["counter"] = base + 1
                return result
            if result != "InvalidAuthenticationCode":
                return result
        return result

    enrol_result = _poll(_enrol, lambda c: c is _SUCCEEDED or c != "InvalidAuthenticationCode",
                         timeout_s=_budget_s(ctx, 240.0), interval_s=1.0,
                         description="the virtual MFA device was enrolled with two live TOTP codes",
                         budgeted=True)
    assert enrol_result is _SUCCEEDED, (
        f"the MFA device could not be enrolled with codes computed from its own seed: "
        f"{enrol_result!r}")

    # --- An MFA-bearing session, via the SAME plain key's exempted sts:GetSessionToken.
    def _get_session_token():
        window = max(int(time.time()) // _TOTP_STEP, consumed["counter"] + 1)
        try:
            return plain_iam_sts.get_session_token(
                SerialNumber=mfa_arn, TokenCode=_totp(seed, window * _TOTP_STEP),
                DurationSeconds=900)
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code")

    plain_iam_sts = _client_with_credentials("sts", plain_creds)
    session = _poll(_get_session_token, lambda r: isinstance(r, dict),
                    timeout_s=_budget_s(ctx, 240.0), interval_s=1.0,
                    description="GetSessionToken accepted a live TOTP code", budgeted=True)
    assert session["Credentials"]["AccessKeyId"].startswith("ASIA"), (
        "an MFA-bearing GetSessionToken must return a temporary key in the ASIA class; got "
        f"prefix {session['Credentials']['AccessKeyId'][:4]!r}")

    _wait_creds_active(session["Credentials"])
    mfa_ident = _client_with_credentials("sts", session["Credentials"]).get_caller_identity()
    assert mfa_ident["Arn"] == user_arn, (
        f"the MFA session must still be the SAME IAM user, not a different identity; got "
        f"{mfa_ident['Arn']!r}, expected {user_arn!r}")

    # --- POSITIVE half: the identical action, identical resource, same identity -- now permitted.
    mfa_s3 = _client_with_credentials("s3", session["Credentials"])
    _poll_allowed(lambda: mfa_s3.put_object(Bucket=bucket, Key=mfa_key, Body=payload),
                  what="s3:PutObject by the MFA-bearing session")
    mfa_body = mfa_s3.get_object(Bucket=bucket, Key=mfa_key)["Body"].read()
    assert mfa_body == payload, (
        f"the MFA-permitted write must round-trip its exact bytes; got {mfa_body!r} instead of "
        f"{payload!r}")

    # --- STILL denied: the plain key, re-checked after the MFA leg, so the first denial was about
    # the absent MFA context key and not about transient propagation that later cleared on its own.
    still_plain_code, still_plain_message = _denial(
        lambda: plain_s3.put_object(Bucket=bucket, Key=plain_key, Body=payload))
    assert (still_plain_code, still_plain_message) == (plain_code, plain_message), (
        f"the plain session's denial must be stable; first saw {(plain_code, plain_message)!r}, "
        f"now {(still_plain_code, still_plain_message)!r}")

    # --- EFFECT SCOPING: the owner sees exactly the one object the MFA session created, never the
    # one the plain session attempted.
    owner_mfa_body = s3.get_object(Bucket=bucket, Key=mfa_key)["Body"].read()
    assert owner_mfa_body == payload, (
        f"the object written by the MFA session must be intact and owner-readable; got "
        f"{owner_mfa_body!r}")
    owner_plain_code = _outcome(lambda: s3.head_object(Bucket=bucket, Key=plain_key))
    assert owner_plain_code == "404", (
        f"the plain session's object must still not exist; HeadObject returned {owner_plain_code!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
