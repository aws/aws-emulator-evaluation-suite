"""securestring-under-a-disabled-cmk-is-neither-decrypted-nor-written."""

from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "securestring-under-a-disabled-cmk-is-neither-decrypted-nor-written"
GROUP = "parameter-store"
SERVICES = ["kms", "ssm"]

_MARK = [{"Key": "sim2real", "Value": CHECK}]
_PLAINTEXT = "sim2real-behav-disabled-cmk-plaintext"
_REWRITE = "sim2real-behav-disabled-cmk-rewrite"

#: SSM surfaces KMS's DisabledException as InvalidKeyId; {key} is the key ARN and the KMS request
#: id is masked to {request_id}.
_DISABLED = (
    "InvalidKeyId",
    "{key} is disabled. (Service: AWSKMS; Status Code: 400; Error Code: DisabledException; "
    "Request ID: {request_id}; Proxy: null)",
)
_REQUEST_ID = re.compile(r"Request ID: [0-9a-fA-F-]+;")
#: Bound on a DisableKey reaching SSM's decrypt path; KMS key state is eventually consistent.
_KEY_STATE_S = 40.0
_OK = ("OK", "")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SSM refuses to decrypt or write a SecureString under a disabled customer managed key.

    GetParameter WithDecryption and PutParameter naming the key fail; no new version is written.
    Reference: https://docs.aws.amazon.com/kms/latest/developerguide/enabling-keys.html
    """
    kms = ctx.client("kms")
    ssm = ctx.client("ssm")

    key = {}
    ctx.on_cleanup(lambda: _schedule_key_deletion(kms, key))
    key["arn"] = key_arn = kms.create_key(
        Description="sim2real-behav disabled-cmk securestring",
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]["Arn"]

    name = "/" + ctx.unique_name("sim2real-behav-disabled-cmk-")
    ctx.on_cleanup(lambda: _delete_parameter(ssm, name))
    ssm.put_parameter(Name=name, Value=_PLAINTEXT, Type="SecureString", KeyId=key_arn, Tags=_MARK)

    # Positive control: while the key is enabled the same read decrypts.
    readable = ssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]
    assert readable["Value"] == _PLAINTEXT and readable["Version"] == 1, (
        f"under an enabled key GetParameter WithDecryption must return version 1 with the "
        f"plaintext; got Value={readable['Value']!r} Version={readable['Version']!r}"
    )

    kms.disable_key(KeyId=key_arn)
    state = kms.describe_key(KeyId=key_arn)["KeyMetadata"]["KeyState"]
    assert state == "Disabled", f"DisableKey must leave KeyState 'Disabled'; got {state!r}"

    expected = (_DISABLED[0], _DISABLED[1].format(key=key_arn, request_id="{request_id}"))
    read = _poll(
        ctx,
        lambda: _outcome(lambda: ssm.get_parameter(Name=name, WithDecryption=True)),
        lambda o: o != _OK,
        description="GetParameter WithDecryption is refused under the disabled key",
    )
    assert read == expected, (
        f"GetParameter WithDecryption under the disabled key must be refused with exactly "
        f"{expected!r}; got {read!r}"
    )

    # Run after the read is refused, so the disable has reached SSM.
    write = _refused(
        lambda: ssm.put_parameter(
            Name=name, Value=_REWRITE, Type="SecureString", KeyId=key_arn, Overwrite=True
        )
    )
    assert write == expected, (
        f"PutParameter SecureString naming the disabled key must be refused with exactly "
        f"{expected!r}; got {write!r}"
    )

    # The refused write left the parameter at its first version.
    meta = ssm.get_parameter(Name=name, WithDecryption=False)["Parameter"]
    assert meta["Version"] == 1, (
        f"the refused PutParameter must not create a version; GetParameter reports Version "
        f"{meta['Version']!r}"
    )


def _outcome(fn):
    """``(code, message)`` of the call's error, KMS request id masked, or ``("OK", "")``."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), _REQUEST_ID.sub("Request ID: {request_id};", err.get("Message", ""))
    return _OK


def _refused(fn):
    """``(code, message)`` of a refused call, KMS request id masked; a success raises."""
    got = _outcome(fn)
    if got == _OK:
        raise AssertionError("real AWS refuses this call, but it SUCCEEDED")
    return got


def _poll(ctx, probe, predicate, *, description, interval_s=2.0):
    """Poll until predicate holds, within min(40 s, the run's remaining time less 5 s)."""
    left = ctx.time_left()
    timeout_s = _KEY_STATE_S if left is None else max(1.0, min(_KEY_STATE_S, left - 5.0))
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            if left is not None and ctx.time_left() <= 6.0:
                raise TimeoutError(f"run budget ended while waiting: {description}")
            raise AssertionError(f"{description} not within {timeout_s:.0f}s; last {last!r}")
        time.sleep(interval_s)
        last = probe()
    return last


def _schedule_key_deletion(kms, key):
    """Teardown: schedule deletion of the key once CreateKey has returned its ARN."""
    if "arn" in key:
        kms.schedule_key_deletion(KeyId=key["arn"], PendingWindowInDays=7)


def _delete_parameter(ssm, name):
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ParameterNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
