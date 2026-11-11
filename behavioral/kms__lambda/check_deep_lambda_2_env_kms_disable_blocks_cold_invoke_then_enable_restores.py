"""deep-lambda-2-env-kms-disable-blocks-cold-invoke-then-enable-restores."""

from __future__ import annotations

import io
import json
import time
import uuid
import zipfile

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "deep-lambda-2-env-kms-disable-blocks-cold-invoke-then-enable-restores"
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

# The handler never calls KMS itself: the only decryption is the one Lambda performs while
# building the execution environment.
_HANDLER_SRC = (
    "import os\n"
    "\n"
    "def handler(event, context):\n"
    "    return {'secret': os.environ.get('SECRET')}\n"
)


def _code_of(exc):
    return exc.response.get("Error", {}).get("Code")


def _zipped(src):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", src)
    return buf.getvalue()


def _poll(probe, done, *, timeout_s, interval_s=3.0, what="condition"):
    """Poll probe() until done(result); return the result, or fail quoting the last one."""
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
    """Delete /aws/lambda/<fn> in a loop, since a buffered flush can recreate it after one delete.

    Registered before the function so LIFO cleanup runs it after DeleteFunction.
    """
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


def _create_key(ctx):
    """Create a symmetric CMK; a disabled key can be scheduled for deletion without re-enabling."""
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description="sim2real-xsvc lambda env-var CMK disable/enable propagation",
        Tags=[{"TagKey": k, "TagValue": v} for k, v in _MANAGED_TAGS.items()],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: ctx.client("kms").schedule_key_deletion(
        KeyId=meta["KeyId"], PendingWindowInDays=7))
    return meta["Arn"]


def _create_role(ctx, key_arn):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-xsvc-envkms-role-")
    arn = iam.create_role(
        RoleName=name,
        Path="/sim2real/",
        AssumeRolePolicyDocument=json.dumps(_LAMBDA_TRUST),
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    iam.put_role_policy(
        RoleName=name,
        PolicyName="decrypt-env",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["kms:Decrypt"], "Resource": key_arn}],
        }),
    )
    return arn


def _create_function(ctx, lam, role_arn, key_arn, marker):
    """CreateFunction, retrying ONLY the IAM role-propagation window, then wait for Active."""
    fn_name = ctx.unique_name("sim2real-xsvc-envkms-fn-")
    ctx.on_cleanup(lambda: _reap_log_group(ctx, fn_name))
    deadline = time.monotonic() + 120
    while True:
        try:
            lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Handler="index.handler",
                Role=role_arn,
                Code={"ZipFile": _zipped(_HANDLER_SRC)},
                Timeout=10,
                MemorySize=128,
                KMSKeyArn=key_arn,
                Environment={"Variables": {"SECRET": marker}},
                Description="sim2real-xsvc env-var CMK propagation",
                Tags=dict(_MANAGED_TAGS),
            )
            break
        except ClientError as exc:
            msg = exc.response.get("Error", {}).get("Message", "")
            if (_code_of(exc) != "InvalidParameterValueException" or "cannot be assumed" not in msg
                    or time.monotonic() >= deadline):
                raise
            time.sleep(4)
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    cfg = _poll(lambda: lam.get_function_configuration(FunctionName=fn_name),
                lambda c: c.get("State") in ("Active", "Failed"),
                timeout_s=120, what=f"{fn_name} leaving State=Pending")
    assert cfg["State"] == "Active", f"function entered {cfg['State']!r}: {cfg.get('StateReason')!r}"
    return fn_name


def _kms_disabled_invoke_message(key_arn, actual):
    """Build the exact Invoke refusal text for an environment whose CMK is disabled.

    The relayed KMS request id is the only per-call token, so it is taken from the actual message.
    """
    _, _, tail = (actual or "").partition("Request ID: ")
    request_id = tail[:36]
    try:
        uuid.UUID(request_id)
    except ValueError:
        request_id = "<a KMS request id>"
    return (
        "Lambda was unable to decrypt the environment variables because the KMS key used is "
        "disabled. Please check the function's KMS key settings. KMS Exception: "
        f"DisabledExceptionKMS Message: {key_arn} is disabled. (Service: Kms, Status Code: 400, "
        f"Request ID: {request_id}) (SDK Attempt Count: 1)"
    )


def _invoke(lam, fn_name):
    """One synchronous Invoke. Returns ('ok', payload) or ('error', code, http_status, message)."""
    try:
        resp = lam.invoke(FunctionName=fn_name, InvocationType="RequestResponse", Payload=b"{}")
    except ClientError as exc:
        return ("error", _code_of(exc), exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
                exc.response.get("Error", {}).get("Message"))
    body = resp["Payload"].read()
    assert resp.get("StatusCode") == 200 and not resp.get("FunctionError"), (
        f"Invoke returned StatusCode={resp.get('StatusCode')!r} "
        f"FunctionError={resp.get('FunctionError')!r}: {body[:400]!r}"
    )
    return ("ok", json.loads(body))


def _force_new_environment(lam, fn_name, timeout_s):
    """Change Timeout so the next Invoke builds a new sandbox.

    Lambda decrypts at environment build, so a warm sandbox keeps its plaintext after DisableKey.
    """
    lam.update_function_configuration(FunctionName=fn_name, Timeout=timeout_s)
    _poll(lambda: lam.get_function_configuration(FunctionName=fn_name),
          lambda c: c.get("LastUpdateStatus") in ("Successful", "Failed"),
          timeout_s=120, what=f"{fn_name} config update to settle")


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Disabling the CMK that encrypts a function's environment variables blocks a cold Invoke
    with KMSDisabledException (502) and surfaces Environment.Error on the configuration;
    re-enabling the key restores the identical Invoke.
    """
    lam = ctx.client("lambda")
    # Retries off: botocore retries a 502 four times, which only hides the first answer.
    lam_once = ctx.client("lambda", config=Config(retries={"max_attempts": 1, "mode": "standard"}))
    kms = ctx.client("kms")
    marker = ctx.unique_name("sim2real-envkms-marker-")

    key_arn = _create_key(ctx)
    role_arn = _create_role(ctx, key_arn)
    fn_name = _create_function(ctx, lam, role_arn, key_arn, marker)

    cfg = lam.get_function_configuration(FunctionName=fn_name)
    assert cfg.get("KMSKeyArn") == key_arn, f"KMSKeyArn not echoed: {cfg.get('KMSKeyArn')!r}"
    env = cfg.get("Environment") or {}
    assert env.get("Variables", {}).get("SECRET") == marker and "Error" not in env, (
        f"with the key enabled the configuration must show the decrypted variable and no error: {env!r}"
    )

    first = _poll(lambda: _invoke(lam_once, fn_name), lambda r: r[0] == "ok",
                  timeout_s=60, what="first Invoke to succeed with the key enabled")
    assert first[1] == {"secret": marker}, f"handler saw {first[1]!r}, expected the marker {marker!r}"

    kms.disable_key(KeyId=key_arn)
    broken_cfg = _poll(lambda: lam.get_function_configuration(FunctionName=fn_name),
                       lambda c: "Error" in (c.get("Environment") or {}),
                       timeout_s=120, what="Environment.Error after DisableKey")
    benv = broken_cfg["Environment"]
    assert benv["Error"].get("ErrorCode") == "DisabledException", (
        f"Environment.Error must name the KMS DisabledException: {benv!r}"
    )
    expected_env_message = (
        "Lambda was unable to decrypt your environment variables because the KMS key used is "
        "disabled. Please check your KMS key settings. KMS Exception: DisabledException KMS "
        f"Message: {key_arn} is disabled."
    )
    assert benv["Error"].get("Message") == expected_env_message, (
        f"Environment.Error.Message must be {expected_env_message!r}: {benv!r}"
    )
    assert "Variables" not in benv, (
        f"a disabled key must not leave the plaintext readable through GetFunctionConfiguration: {benv!r}"
    )

    _force_new_environment(lam, fn_name, 11)
    denied = _poll(lambda: _invoke(lam_once, fn_name), lambda r: r[0] == "error",
                   timeout_s=120, what="a cold Invoke to fail after DisableKey")
    assert denied[1] == "KMSDisabledException", f"expected KMSDisabledException, got {denied!r}"
    assert denied[2] == 502, f"KMSDisabledException must be HTTP 502, got {denied!r}"
    expected = _kms_disabled_invoke_message(key_arn, denied[3])
    assert denied[3] == expected, f"Invoke refusal message must be {expected!r}, got {denied[3]!r}"
    # The effect is absent on every retry, not only once.
    again = _invoke(lam_once, fn_name)
    assert again[:3] == denied[:3], (
        f"a second Invoke with the key disabled returned {again!r}, not {denied!r}"
    )
    expected = _kms_disabled_invoke_message(key_arn, again[3])
    assert again[3] == expected, (
        f"the second Invoke refusal message must be {expected!r}, got {again[3]!r}"
    )

    kms.enable_key(KeyId=key_arn)
    restored = _poll(lambda: _invoke(lam_once, fn_name), lambda r: r[0] == "ok",
                     timeout_s=180, interval_s=5, what="Invoke to recover after EnableKey")
    assert restored[1] == {"secret": marker}, (
        f"after EnableKey the handler saw {restored[1]!r}, expected the marker {marker!r}"
    )
    renv = _poll(lambda: lam.get_function_configuration(FunctionName=fn_name).get("Environment") or {},
                 lambda e: "Error" not in e, timeout_s=60, what="Environment.Error to clear")
    assert renv.get("Variables", {}).get("SECRET") == marker, (
        f"after EnableKey the configuration must show the variable again: {renv!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
