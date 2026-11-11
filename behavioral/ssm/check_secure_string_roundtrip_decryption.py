"""secure-string-roundtrip-decryption."""
from __future__ import annotations

import base64
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "secure-string-roundtrip-decryption"
GROUP = 'state-machine'
SERVICES = ['ssm']


def _looks_like_ciphertext(value, plaintext, where):
    """A KMS ciphertext blob, base64-encoded: decodable, binary, and not the plaintext."""
    assert isinstance(value, str) and value, f"{where}: expected a non-empty string, got {value!r}"
    assert plaintext not in value, (
        f"{where}: the plaintext leaked into an undecrypted read: {value!r}"
    )
    assert value not in ("", "REDACTED", "****", "encrypted"), (
        f"{where}: a placeholder is not a ciphertext; got {value!r}"
    )
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:  # noqa: BLE001 -- the assertion is the point
        raise AssertionError(
            f"{where}: an undecrypted SecureString value must be a base64-encoded KMS "
            f"ciphertext blob; {value!r} is not base64 ({exc})"
        )
    assert len(raw) > len(plaintext), (
        f"{where}: a KMS ciphertext blob carries key metadata and must be longer than the "
        f"{len(plaintext)}-byte plaintext; decoded {len(raw)} bytes"
    )
    assert plaintext.encode() not in raw, (
        f"{where}: the plaintext is recoverable from the returned blob by base64-decoding it"
    )


def _error(fn):
    """(Error.Code, HTTP status, Error.Message) of the ClientError fn raises; RAISES on success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), status, err.get("Message") or ""
    raise AssertionError(f"the call was expected to be refused but it succeeded: {result!r}")


def _delete_if_present(ssm, name):
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ParameterNotFound":
            raise


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A SecureString parameter decrypts back to the original plaintext value, and an
    undecrypted read never leaks that plaintext behind a placeholder -- it comes back as a
    genuine base64-encoded KMS ciphertext blob."""

    ssm = ctx.client("ssm")
    plaintext = "super-secret"

    def _param_name(suffix=""):
        # SSM requires a leading '/' for any hierarchical (slash-containing) name.
        return "/" + ctx.unique_name("sim2real-behav-" + suffix)

    def _track_parameter(name):
        ctx.on_cleanup(lambda: _delete_if_present(ssm, name))
        return name

    name = _param_name("probe-param-secure-")
    _track_parameter(name)

    ssm.put_parameter(
        Name=name,
        Value=plaintext,
        Type="SecureString",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )

    decrypted = ssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]
    assert decrypted["Value"] == plaintext, (
        f"WithDecryption=True must return the original plaintext, got {decrypted['Value']!r}"
    )
    assert decrypted["Type"] == "SecureString", decrypted

    # Without decryption, the value must be a genuine ciphertext blob -- not a placeholder,
    # not the plaintext, and not decodable back to it.
    encrypted = ssm.get_parameter(Name=name, WithDecryption=False)["Parameter"]
    _looks_like_ciphertext(encrypted["Value"], plaintext, "GetParameter(WithDecryption=False)")

    ssm.delete_parameter(Name=name)

    # Gone: real AWS sends this ParameterNotFound with no message body, so code + status grade.
    code, status, message = _error(lambda: ssm.get_parameter(Name=name, WithDecryption=True))
    assert (code, status) == ("ParameterNotFound", 400), (
        f"GetParameter(WithDecryption=True) after the delete: expected ParameterNotFound / "
        f"HTTP 400, got {code!r} / {status!r}"
    )
    expected_message = ""
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"
    # DescribeParameters is eventually consistent, so absence is a bounded poll.
    deadline = time.monotonic() + 60.0
    while True:
        described = [
            p["Name"]
            for page in ssm.get_paginator("describe_parameters").paginate(
                ParameterFilters=[{"Key": "Name", "Option": "Equals", "Values": [name]}]
            )
            for p in page.get("Parameters", [])
        ]
        if described == [] or time.monotonic() >= deadline:
            break
        time.sleep(2.0)
    assert described == [], f"DescribeParameters still lists the deleted {name}: {described!r}"
    # Unusable: PutParameter would recreate, so label the dead version instead.
    code, status, message = _error(
        lambda: ssm.label_parameter_version(Name=name, ParameterVersion=1, Labels=["sim2real-dead"])
    )
    assert (code, status) == ("ParameterNotFound", 400), (
        f"LabelParameterVersion on the deleted {name}: expected ParameterNotFound / HTTP 400, "
        f"got {code!r} / {status!r}"
    )
    expected_message = f"Parameter {name} not found."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
