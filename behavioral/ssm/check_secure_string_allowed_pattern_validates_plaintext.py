"""secure-string-allowed-pattern-validates-plaintext."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "secure-string-allowed-pattern-validates-plaintext"
GROUP = 'overly-permissive'
SERVICES = ['ssm']

# A base64 KMS ciphertext blob can never satisfy a digits-only pattern, so acceptance proves the
# pattern is matched against the plaintext.
_DIGIT_PATTERN = "^[0-9]+$"
_MATCHING_PLAINTEXT = "20261030"
_MISMATCHING_PLAINTEXT = "not-a-number"


def _error_code(fn):
    """Return the (code, message) of the ClientError fn raises; raise if it unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(
        f"expected a ClientError, but the call SUCCEEDED and returned {result!r}"
    )


def _param_name(ctx, suffix=""):
    # SSM requires a leading '/' for any hierarchical (slash-containing) name.
    return "/" + ctx.unique_name("sim2real-behav-" + suffix)


def _track_parameter(ctx, ssm, name):
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=name))
    return name


def _delete_if_present(ssm, name):
    """Delete a parameter that should have been refused; absent is success."""
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ParameterNotFound":
            raise


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """SecureString AllowedPattern is checked against the plaintext before encryption: a numeric
    value passes a digits-only pattern, a non-numeric one is refused and changes nothing.
    """

    ssm = ctx.client("ssm")

    # --- positive: a plaintext matching the pattern succeeds ---------------------
    name = _param_name(ctx, "securestring-pattern-")
    _track_parameter(ctx, ssm, name)
    kms = ctx.client("kms")
    key_id = kms.create_key(Description=name)["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    created = ssm.put_parameter(
        Name=name,
        Value=_MATCHING_PLAINTEXT,
        Type="SecureString",
        AllowedPattern=_DIGIT_PATTERN,
        KeyId=key_id,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    assert created["Version"] == 1, (
        "a SecureString plaintext satisfying AllowedPattern must be accepted; if the pattern "
        f"were (wrongly) checked against the ciphertext this would always be refused, got {created!r}"
    )
    decrypted = ssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]
    assert decrypted["Value"] == _MATCHING_PLAINTEXT, (
        f"GetParameter(WithDecryption=True) must return the exact plaintext that passed "
        f"validation, got {decrypted['Value']!r}"
    )
    assert decrypted["Type"] == "SecureString", decrypted

    history = ssm.get_parameter_history(Name=name, WithDecryption=True)["Parameters"]
    assert len(history) == 1, history
    assert history[0].get("AllowedPattern") == _DIGIT_PATTERN, (
        "GetParameterHistory must report the AllowedPattern enforced against this version, "
        f"got {history[0].get('AllowedPattern')!r}"
    )
    assert history[0]["Value"] == _MATCHING_PLAINTEXT, (
        f"the decrypted history entry must carry the plaintext, got {history[0]['Value']!r}"
    )

    # --- break exactly one thing: an overwrite whose plaintext fails the pattern -
    code, message = _error_code(
        lambda: ssm.put_parameter(
            Name=name,
            Value=_MISMATCHING_PLAINTEXT,
            Type="SecureString",
            AllowedPattern=_DIGIT_PATTERN,
            Overwrite=True,
        )
    )
    assert code == "ParameterPatternMismatchException", (
        "a SecureString overwrite whose plaintext fails AllowedPattern must be refused with "
        f"ParameterPatternMismatchException, got {code!r}"
    )
    expected_message = (
        f"Parameter value, cannot be validated against allowedPattern: {_DIGIT_PATTERN}"
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # --- effect absent: the refused overwrite burns no version, changes nothing -
    after = ssm.get_parameter(Name=name, WithDecryption=True)["Parameter"]
    assert after["Value"] == _MATCHING_PLAINTEXT, (
        f"the refused overwrite must not change the stored plaintext, got {after['Value']!r}"
    )
    assert after["Version"] == 1, (
        f"the refused overwrite must not mint a new version, got Version {after['Version']}"
    )
    after_history = ssm.get_parameter_history(Name=name)["Parameters"]
    assert len(after_history) == 1, (
        f"the refused overwrite must not append a history entry, got {len(after_history)}"
    )

    # --- a brand-new SecureString with a non-matching plaintext is refused too --
    never = _param_name(ctx, "securestring-pattern-never-")
    ctx.on_cleanup(lambda: _delete_if_present(ssm, never))
    never_code, never_message = _error_code(
        lambda: ssm.put_parameter(
            Name=never,
            Value=_MISMATCHING_PLAINTEXT,
            Type="SecureString",
            AllowedPattern=_DIGIT_PATTERN,
        )
    )
    assert never_code == "ParameterPatternMismatchException", never_code
    assert never_message == expected_message, never_message
    never_absent, never_absent_message = _error_code(lambda: ssm.get_parameter(Name=never))
    assert never_absent == "ParameterNotFound", (
        f"the refused first-write SecureString must not have been created, got {never_absent!r}"
    )
    assert never_absent_message == "", never_absent_message


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
