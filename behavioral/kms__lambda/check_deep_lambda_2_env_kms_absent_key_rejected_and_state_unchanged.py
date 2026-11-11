"""deep-lambda-2-env-kms-absent-key-rejected-and-state-unchanged."""

from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "deep-lambda-2-env-kms-absent-key-rejected-and-state-unchanged"
GROUP = "env-encryption"
SERVICES = ["kms", "lambda"]


_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}

_LAMBDA_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
}

_HANDLER_SRC = (
    "import os\n"
    "\n"
    "def handler(event, context):\n"
    "    return {'secret': os.environ.get('SECRET')}\n"
)


class _Accepted(Exception):
    """Raised when a call AWS is expected to reject was accepted."""


def _code_of(exc):
    return exc.response.get("Error", {}).get("Code")


def _rejection(fn):
    """Call fn(); return (code, message) of the ClientError, or raise _Accepted with the response."""
    try:
        resp = fn()
    except ClientError as exc:
        return _code_of(exc), exc.response.get("Error", {}).get("Message", "")
    raise _Accepted(repr(resp)[:600])


def _lambda_kms_not_found(kms_message):
    """Lambda's exact refusal when the environment-variable CMK does not exist in KMS."""
    return (
        "Lambda was unable to encrypt your environment variables because the KMS key was not "
        "found. Please check your KMS key settings. KMS Exception: NotFoundException KMS "
        f"Message: {kms_message}"
    )


def _zipped(src):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", src)
    return buf.getvalue()


def _poll(probe, done, *, timeout_s, interval_s=3.0, what="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not observed within {timeout_s}s; last={last!r}")
        time.sleep(interval_s)


def _delete_role(iam, name):
    try:
        for pol in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=name, PolicyName=pol)
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if _code_of(exc) != "NoSuchEntity":
            raise


def _reap_log_group(ctx, fn_name):
    """Delete /aws/lambda/<fn> in a LOOP: a buffered flush can recreate it after one delete."""
    logs = ctx.client("logs")
    name = f"/aws/lambda/{fn_name}"
    quiet = 0
    for _ in range(10):
        try:
            logs.delete_log_group(logGroupName=name)
            quiet = 0
        except ClientError as exc:
            if _code_of(exc) != "ResourceNotFoundException":
                raise
            quiet += 1
            if quiet >= 3:
                return
        time.sleep(3)
    raise RuntimeError(f"log group {name} kept reappearing after DeleteFunction")


def _delete_function_quietly(lam, fn_name):
    try:
        lam.delete_function(FunctionName=fn_name)
    except ClientError as exc:
        if _code_of(exc) != "ResourceNotFoundException":
            raise


def _function_kwargs(fn_name, role_arn, key_arn, marker):
    return dict(
        FunctionName=fn_name,
        Runtime="python3.12",
        Handler="index.handler",
        Role=role_arn,
        Code={"ZipFile": _zipped(_HANDLER_SRC)},
        Timeout=10,
        MemorySize=128,
        KMSKeyArn=key_arn,
        Environment={"Variables": {"SECRET": marker}},
        Description="sim2real-xsvc env-var CMK absent key",
        Tags=dict(_MANAGED_TAGS),
    )


def _invoke_ok(lam, fn_name):
    resp = lam.invoke(FunctionName=fn_name, InvocationType="RequestResponse", Payload=b"{}")
    body = resp["Payload"].read()
    assert resp.get("StatusCode") == 200 and not resp.get("FunctionError"), (
        f"Invoke returned StatusCode={resp.get('StatusCode')!r} "
        f"FunctionError={resp.get('FunctionError')!r}: {body[:400]!r}"
    )
    return json.loads(body)


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A KMSKeyArn naming a non-existent key is refused at CreateFunction and at
    UpdateFunctionConfiguration with KMS's NotFoundException carried through, because Lambda asks
    KMS when it encrypts the variables; neither refusal creates or changes any function.
    """
    lam = ctx.client("lambda")
    kms = ctx.client("kms")
    iam = ctx.client("iam")
    marker = ctx.unique_name("sim2real-envkms-marker-")

    key_meta = kms.create_key(
        Description="sim2real-xsvc lambda env-var CMK absent-key control",
        Tags=[{"TagKey": k, "TagValue": v} for k, v in _MANAGED_TAGS.items()],
    )["KeyMetadata"]
    key_arn = key_meta["Arn"]
    ctx.on_cleanup(lambda: ctx.client("kms").schedule_key_deletion(
        KeyId=key_arn, PendingWindowInDays=7))
    # Same account, same region, same ARN shape as the real key: only KMS's answer differs.
    absent_arn = key_arn.rsplit("/", 1)[0] + "/" + str(uuid.uuid4())
    assert absent_arn != key_arn and absent_arn.startswith(key_arn.split(":key/")[0]), (
        f"fabricated ARN {absent_arn!r} must share the real key's account/region prefix {key_arn!r}"
    )
    unknown = _rejection(lambda: kms.describe_key(KeyId=absent_arn))
    absent_message = f"Key '{absent_arn}' does not exist"
    expected_unknown = ("NotFoundException", absent_message)
    assert unknown == expected_unknown, f"KMS must not know the fabricated key, got {unknown!r}"

    role_name = ctx.unique_name("sim2real-xsvc-envkms-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        Path="/sim2real/",
        AssumeRolePolicyDocument=json.dumps(_LAMBDA_TRUST),
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="decrypt-env",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["kms:Decrypt"], "Resource": key_arn}],
        }),
    )

    # The control with the real key goes first so it also absorbs IAM role propagation.
    good_fn = ctx.unique_name("sim2real-xsvc-envkms-fn-")
    ctx.on_cleanup(lambda: _reap_log_group(ctx, good_fn))
    deadline = time.monotonic() + 120
    while True:
        try:
            lam.create_function(**_function_kwargs(good_fn, role_arn, key_arn, marker))
            break
        except ClientError as exc:
            msg = exc.response.get("Error", {}).get("Message", "")
            if (_code_of(exc) != "InvalidParameterValueException" or "cannot be assumed" not in msg
                    or time.monotonic() >= deadline):
                raise
            time.sleep(4)
    ctx.on_cleanup(lambda: _delete_function_quietly(lam, good_fn))
    cfg = _poll(lambda: lam.get_function_configuration(FunctionName=good_fn),
                lambda c: c.get("State") in ("Active", "Failed"),
                timeout_s=120, what=f"{good_fn} leaving State=Pending")
    assert cfg["State"] == "Active", f"control function entered {cfg['State']!r}"
    # The first Invoke can fail with KMSAccessDeniedException while the role's kms:Decrypt
    # propagates, so retry exactly that, bounded.
    deadline = time.monotonic() + 120
    while True:
        try:
            first = _invoke_ok(lam, good_fn)
            break
        except ClientError as exc:
            if _code_of(exc) != "KMSAccessDeniedException" or time.monotonic() >= deadline:
                raise
            time.sleep(5)
    assert first == {"secret": marker}, f"control function must echo the marker, got {first!r}"

    # The rejection is synchronous at CreateFunction, so an absent key never reaches Invoke.
    bad_fn = ctx.unique_name("sim2real-xsvc-envkms-absent-")
    ctx.on_cleanup(lambda: _reap_log_group(ctx, bad_fn))
    ctx.on_cleanup(lambda: _delete_function_quietly(lam, bad_fn))
    try:
        code, msg = _rejection(
            lambda: lam.create_function(**_function_kwargs(bad_fn, role_arn, absent_arn, marker)))
    except _Accepted as acc:
        raise AssertionError(
            f"CreateFunction ACCEPTED a KMSKeyArn KMS does not hold (over-permissive): {acc}"
        ) from None
    expected_create = ("InvalidParameterValueException", _lambda_kms_not_found(absent_message))
    assert (code, msg) == expected_create, (
        f"expected {expected_create!r} for an absent CMK, got {(code, msg)!r}"
    )
    gone = _rejection(lambda: lam.get_function(FunctionName=bad_fn))
    function_arn = f"arn:aws:lambda:{lam.meta.region_name}:{ctx.account}:function:{bad_fn}"
    expected_gone = ("ResourceNotFoundException", f"Function not found: {function_arn}")
    assert gone == expected_gone, (
        f"a refused CreateFunction must create nothing; GetFunction returned {gone!r}"
    )

    try:
        ucode, umsg = _rejection(lambda: lam.update_function_configuration(
            FunctionName=good_fn, KMSKeyArn=absent_arn))
    except _Accepted as acc:
        raise AssertionError(
            f"UpdateFunctionConfiguration ACCEPTED an absent KMSKeyArn (over-permissive): {acc}"
        ) from None
    expected_update = ("InvalidParameterValueException", _lambda_kms_not_found(absent_message))
    assert (ucode, umsg) == expected_update, (
        f"expected {expected_update!r} re-keying to an absent CMK, got {(ucode, umsg)!r}"
    )
    after = lam.get_function_configuration(FunctionName=good_fn)
    assert after.get("KMSKeyArn") == key_arn, (
        f"a refused update must leave KMSKeyArn on the real key, found {after.get('KMSKeyArn')!r}"
    )
    assert (after.get("Environment") or {}).get("Variables", {}).get("SECRET") == marker, (
        f"a refused update must leave the variables intact: {after.get('Environment')!r}"
    )
    assert _invoke_ok(lam, good_fn) == {"secret": marker}, (
        "after the refused re-key the function must still serve the marker"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
