"""create-secret-conflicting-secret-value-params-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-secret-conflicting-secret-value-params-rejected"
GROUP = "overly-permissive"
SERVICES = ["secretsmanager"]

_BOTH_VALUES_MESSAGE = (
    "You can't specify both a binary secret value and a string secret value in the same secret."
)


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """CreateSecret and PutSecretValue with both SecretString and SecretBinary are rejected and
    change nothing; each representation alone round-trips without populating the other field.
    """
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-secmgr-conflict-")

    code, message = _refusal(
        lambda: sm.create_secret(Name=name, SecretString="conflict-value", SecretBinary=b"conflict-bytes")
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"
    assert message == _BOTH_VALUES_MESSAGE, f"unexpected refusal message: {message!r}"

    # Effect absent: no secret with this name was actually created.
    not_found_code, not_found_message = _refusal(lambda: sm.describe_secret(SecretId=name))
    assert not_found_code == "ResourceNotFoundException", (
        f"a rejected CreateSecret must not leave a secret behind, got {not_found_code!r}"
    )
    assert not_found_message == "Secrets Manager can't find the specified secret.", (
        f"unexpected not-found message: {not_found_message!r}"
    )

    # Positive control: the same name with only SecretString succeeds normally.
    created = sm.create_secret(
        Name=name, SecretString="clean-value", Tags=[{"Key": "sim2real-owner", "Value": "behavioral-check"}]
    )
    secret_arn = created["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))
    got_str = _read_after_create(lambda: sm.get_secret_value(SecretId=secret_arn))
    assert got_str["SecretString"] == "clean-value", f"expected 'clean-value', got {got_str['SecretString']!r}"
    assert not got_str.get("SecretBinary"), f"expected SecretBinary absent, got {got_str.get('SecretBinary')!r}"

    bin_name = ctx.unique_name("sim2real-behav-secmgr-binrep-")
    raw_bytes = b"\x00\x01\xffbinary-payload-\xfe\xfd"
    created_bin = sm.create_secret(
        Name=bin_name, SecretBinary=raw_bytes, Tags=[{"Key": "sim2real-owner", "Value": "behavioral-check"}]
    )
    bin_arn = created_bin["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=bin_arn, ForceDeleteWithoutRecovery=True))

    got_bin = _read_after_create(lambda: sm.get_secret_value(SecretId=bin_arn))
    assert got_bin["SecretBinary"] == raw_bytes, f"expected {raw_bytes!r}, got {got_bin['SecretBinary']!r}"
    assert not got_bin.get("SecretString"), f"expected SecretString absent, got {got_bin.get('SecretString')!r}"

    raw_bytes_v2 = b"\x02\x03second-version\x9f"
    put = sm.put_secret_value(SecretId=bin_arn, SecretBinary=raw_bytes_v2)
    version2 = put["VersionId"]
    got_bin2 = sm.get_secret_value(SecretId=bin_arn)
    assert got_bin2["SecretBinary"] == raw_bytes_v2, f"expected {raw_bytes_v2!r}, got {got_bin2['SecretBinary']!r}"
    assert got_bin2["VersionId"] == version2, f"expected AWSCURRENT version {version2!r}, got {got_bin2['VersionId']!r}"
    prev = sm.get_secret_value(SecretId=bin_arn, VersionStage="AWSPREVIOUS")
    assert prev["SecretBinary"] == raw_bytes, f"expected AWSPREVIOUS to still be {raw_bytes!r}, got {prev['SecretBinary']!r}"

    conflict_code, conflict_message = _refusal(
        lambda: sm.put_secret_value(SecretId=bin_arn, SecretString="conflict", SecretBinary=b"conflict")
    )
    assert conflict_code == "InvalidParameterException", f"expected InvalidParameterException, got {conflict_code!r}"
    assert conflict_message == _BOTH_VALUES_MESSAGE, f"unexpected refusal message: {conflict_message!r}"
    unchanged = sm.get_secret_value(SecretId=bin_arn)
    assert unchanged["SecretBinary"] == raw_bytes_v2, (
        f"a rejected PutSecretValue must leave the current version untouched, got {unchanged['SecretBinary']!r}"
    )
    assert unchanged["VersionId"] == version2, (
        f"a rejected PutSecretValue must not move AWSCURRENT, got {unchanged['VersionId']!r}"
    )


def _read_after_create(fn, *, timeout_s=10.0, interval_s=0.5):
    """Retry briefly on ResourceNotFoundException; a read right after CreateSecret can lag."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _refusal(fn):
    """Return the refused call's (Error.Code, Error.Message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
