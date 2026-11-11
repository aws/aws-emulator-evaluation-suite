"""secure-string-ciphertext-on-all-read-paths."""
from __future__ import annotations

import base64
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "secure-string-ciphertext-on-all-read-paths"
GROUP = 'overly-permissive'
SERVICES = ['ssm']

# Obviously synthetic and self-labelling: this must never look like a real secret
# in a log, a golden, or an account's parameter list.
_PLAINTEXT = "sim2real-behav-ssm-not-a-real-secret-8f21"


# DescribeParameters is eventually consistent after PutParameter.
def _client_error(fn):
    """Return the ClientError (code, message) fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


def _param_name(ctx, suffix=""):
    # SSM requires a leading '/' for any hierarchical (slash-containing) name.
    return "/" + ctx.unique_name("sim2real-behav-" + suffix)


def _track_parameter(ctx, ssm, name):
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=name))
    return name


def _poll(probe, predicate, timeout_s=90, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"condition not met within {timeout_s}s (last observed: {last!r})"
            )
        time.sleep(interval_s)


def _looks_like_ciphertext(value, where):
    """A KMS ciphertext blob, base64-encoded: decodable, binary, and not the plaintext."""
    assert isinstance(value, str) and value, f"{where}: expected a non-empty string, got {value!r}"
    assert _PLAINTEXT not in value, (
        f"{where}: the plaintext leaked into an undecrypted read: {value!r}"
    )
    assert value not in ("", "REDACTED", "****", "encrypted"), (
        f"{where}: a placeholder is not a ciphertext; got {value!r}"
    )
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:  # noqa: BLE001 — the assertion is the point
        raise AssertionError(
            f"{where}: an undecrypted SecureString value must be a base64-encoded KMS "
            f"ciphertext blob; {value!r} is not base64 ({exc})"
        )
    assert len(raw) > len(_PLAINTEXT), (
        f"{where}: a KMS ciphertext blob carries key metadata and must be longer than the "
        f"{len(_PLAINTEXT)}-byte plaintext; decoded {len(raw)} bytes"
    )
    assert _PLAINTEXT.encode() not in raw, (
        f"{where}: the plaintext is recoverable from the returned blob by base64-decoding it"
    )
    return raw


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A SecureString read with WithDecryption=False returns base64 KMS ciphertext on all four read
    paths, and DescribeParameters (ParameterMetadata has no Value member) returns no value.
    """

    ssm = ctx.client("ssm")

    base = _param_name(ctx, "secure-")
    name = f"{base}/token"
    _track_parameter(ctx, ssm, name)
    kms = ctx.client("kms")
    key_id = kms.create_key(Description=name)["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    put = ssm.put_parameter(
        Name=name,
        Value=_PLAINTEXT,
        Type="SecureString",
        KeyId=key_id,
    )
    assert put["Version"] == 1, put

    # --- path 1: GetParameter ----------------------------------------------
    plain = ssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]
    assert plain["Value"] == _PLAINTEXT, (
        f"WithDecryption=True must return the plaintext, got {plain['Value']!r}"
    )
    assert plain["Type"] == "SecureString", plain
    enc1 = ssm.get_parameter(Name=name, WithDecryption=False)["Parameter"]
    assert enc1["Type"] == "SecureString", enc1
    blob = _looks_like_ciphertext(enc1["Value"], "GetParameter(WithDecryption=False)")

    # The default must be the safe one: WithDecryption is optional and defaults
    # to no decryption.
    enc_default = ssm.get_parameter(Name=name)["Parameter"]
    assert enc_default["Value"] == enc1["Value"], (
        "GetParameter with WithDecryption omitted must behave as WithDecryption=False; "
        f"got {enc_default['Value']!r}"
    )

    # --- path 2: GetParameters (batch) -------------------------------------
    batch_plain = ssm.get_parameters(Names=[name], WithDecryption=True)
    assert batch_plain["InvalidParameters"] == [], batch_plain
    assert [p["Value"] for p in batch_plain["Parameters"]] == [_PLAINTEXT], (
        f"GetParameters(WithDecryption=True) must decrypt, got {batch_plain['Parameters']}"
    )
    batch_enc = ssm.get_parameters(Names=[name], WithDecryption=False)
    assert len(batch_enc["Parameters"]) == 1, batch_enc
    _looks_like_ciphertext(
        batch_enc["Parameters"][0]["Value"], "GetParameters(WithDecryption=False)"
    )

    # --- path 3: GetParametersByPath ---------------------------------------
    _poll(
        lambda: [
            p
            for p in ssm.get_parameters_by_path(
                Path=base, Recursive=True, WithDecryption=False
            )["Parameters"]
            if p["Name"] == name
        ],
        lambda got: len(got) == 1,
    )
    path_enc = [
        p
        for p in ssm.get_parameters_by_path(
            Path=base, Recursive=True, WithDecryption=False
        )["Parameters"]
        if p["Name"] == name
    ][0]
    _looks_like_ciphertext(
        path_enc["Value"], "GetParametersByPath(WithDecryption=False)"
    )
    path_plain = [
        p
        for p in ssm.get_parameters_by_path(
            Path=base, Recursive=True, WithDecryption=True
        )["Parameters"]
        if p["Name"] == name
    ][0]
    assert path_plain["Value"] == _PLAINTEXT, (
        f"GetParametersByPath(WithDecryption=True) must decrypt, got {path_plain['Value']!r}"
    )

    # --- path 4: GetParameterHistory ---------------------------------------
    hist_enc = ssm.get_parameter_history(Name=name, WithDecryption=False)["Parameters"]
    assert len(hist_enc) == 1, f"one version expected in history, got {hist_enc}"
    assert hist_enc[0]["KeyId"], (
        f"a SecureString history entry must report the KeyId it was encrypted under, got {hist_enc[0]}"
    )
    _looks_like_ciphertext(
        hist_enc[0]["Value"], "GetParameterHistory(WithDecryption=False)"
    )
    hist_plain = ssm.get_parameter_history(Name=name, WithDecryption=True)["Parameters"]
    assert hist_plain[0]["Value"] == _PLAINTEXT, (
        f"GetParameterHistory(WithDecryption=True) must decrypt, got {hist_plain[0]['Value']!r}"
    )

    # --- metadata surfaces carry no value at all ---------------------------
    meta = _poll(
        lambda: [
            m
            for m in ssm.describe_parameters(
                ParameterFilters=[
                    {"Key": "Name", "Option": "Equals", "Values": [name]}
                ]
            )["Parameters"]
        ],
        lambda got: len(got) == 1,
    )[0]
    assert "Value" not in meta, (
        "ParameterMetadata has no Value member in the Smithy model; DescribeParameters "
        f"must not return one, got {meta.get('Value')!r}"
    )
    assert meta["Type"] == "SecureString", meta
    assert meta["KeyId"], (
        f"DescribeParameters must report the encryption KeyId for a SecureString, got {meta}"
    )

    # --- control: a String parameter is unaffected by WithDecryption --------
    clear_name = f"{base}/clear"
    _track_parameter(ctx, ssm, clear_name)
    ssm.put_parameter(Name=clear_name, Value="sim2real-behav-clear", Type="String")
    for with_decryption in (True, False):
        got = ssm.get_parameter(Name=clear_name, WithDecryption=with_decryption)[
            "Parameter"
        ]
        assert got["Value"] == "sim2real-behav-clear", (
            f"WithDecryption={with_decryption} must not alter a String parameter, got {got}"
        )

    # --- control: an unknown KMS alias is refused, not silently ignored -----
    bad_key, _ = _client_error(
        lambda: ssm.put_parameter(
            Name=f"{base}/badkey",
            Value=_PLAINTEXT,
            Type="SecureString",
            KeyId="alias/sim2real-behav-no-such-key",
        )
    )
    assert bad_key == "InvalidKeyId", (
        "a SecureString written under a nonexistent KMS alias must be refused with "
        f"InvalidKeyId (the modeled PutParameter error for this condition), got {bad_key!r}"
    )
    # message varies: AWS embeds the per-call KMS request id in the InvalidKeyId message.
    missing_code, missing_message = _client_error(
        lambda: ssm.get_parameter(Name=f"{base}/badkey")
    )
    assert missing_code == "ParameterNotFound", (
        f"the rejected SecureString must not have been created, got {missing_code!r}"
    )
    assert missing_message == "", f"unexpected message {missing_message!r}"

    # Byte-level control on the successful blob: two undecrypted reads of the same
    # version return a stable ciphertext (SSM stores it, it is not re-encrypted
    # per read), so a caller can compare without decrypting.
    assert (
        base64.b64decode(
            ssm.get_parameter(Name=name, WithDecryption=False)["Parameter"]["Value"]
        )
        == blob
    ), "repeated undecrypted reads of one version must return the identical stored ciphertext"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
