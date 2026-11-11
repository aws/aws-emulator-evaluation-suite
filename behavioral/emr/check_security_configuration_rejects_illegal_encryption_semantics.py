"""security-configuration-rejects-illegal-encryption-semantics."""
from __future__ import annotations

import copy
import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "security-configuration-rejects-illegal-encryption-semantics"
GROUP = 'overly-permissive'
SERVICES = ['emr']

THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException")

# EMR uses this code for every security-configuration rejection (malformed JSON,
# duplicate name, missing name), so a semantic rejection is asserted against it too.
EXPECTED_CODE = "InvalidRequestException"

# A payload AWS accepts; each break below is a one-leaf mutation of it. SSE-S3
# needs no KMS key, so no resource but the security configuration is created.
VALID_CONFIG = {
    "EncryptionConfiguration": {
        "EnableInTransitEncryption": False,
        "EnableAtRestEncryption": True,
        "AtRestEncryptionConfiguration": {
            "S3EncryptionConfiguration": {"EncryptionMode": "SSE-S3"}
        },
    }
}


def _error(fn):
    """Invoke fn, asserting it is rejected; return the (code, message) pair."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 — the rejection is the subject
        err = (getattr(exc, "response", {}) or {}).get("Error", {})
        return err.get("Code", type(exc).__name__), err.get("Message", "")
    raise AssertionError("expected the operation to be rejected, but it succeeded")


def _error_stable(fn, attempts: int = 6):
    """Like _error but retries through throttling so the assertion observes the
    operation's real rejection code rather than a rate-limit artefact."""
    code, message = _error(fn)
    for attempt in range(attempts - 1):
        if code not in THROTTLE_CODES:
            break
        time.sleep(5 * (attempt + 1))
        code, message = _error(fn)
    return code, message


def _create_stable(emr, name, payload, attempts: int = 6):
    """CreateSecurityConfiguration, retrying only through throttling."""
    last_exc = None
    for attempt in range(attempts):
        try:
            return emr.create_security_configuration(
                Name=name, SecurityConfiguration=payload
            )
        except Exception as exc:  # noqa: BLE001 — classified, re-raised if fatal
            code = (getattr(exc, "response", {}) or {}).get("Error", {}).get("Code", "")
            if code not in THROTTLE_CODES:
                raise
            last_exc = exc
            time.sleep(5 * (attempt + 1))
    raise AssertionError(f"CreateSecurityConfiguration never succeeded: {last_exc}")


def _names(emr):
    """Every security-configuration name in the account, following the token."""
    out = []
    marker = None
    for _ in range(50):
        kwargs = {"Marker": marker} if marker else {}
        resp = emr.list_security_configurations(**kwargs)
        out.extend(c["Name"] for c in resp.get("SecurityConfigurations", []))
        marker = resp.get("Marker")
        if not marker:
            return out
    raise AssertionError("ListSecurityConfigurations did not terminate in 50 pages")


def _contains(stored, submitted, path="$"):
    """Assert every leaf of `submitted` is present in `stored` with the same value.

    A subset, not equality: EMR returns a re-serialised document that may add fields.
    """
    if isinstance(submitted, dict):
        assert isinstance(stored, dict), (
            f"{path}: expected an object, stored value is {stored!r}"
        )
        for key, value in submitted.items():
            assert key in stored, (
                f"{path}.{key}: submitted setting is missing from the stored "
                f"configuration (stored keys: {sorted(stored)!r})"
            )
            _contains(stored[key], value, f"{path}.{key}")
    else:
        assert stored == submitted, (
            f"{path}: submitted {submitted!r} but the stored configuration reports "
            f"{stored!r}"
        )


def _mutated(**path_value):
    """A deep copy of VALID_CONFIG with exactly one leaf changed or removed."""
    cfg = copy.deepcopy(VALID_CONFIG)
    at_rest = cfg["EncryptionConfiguration"]["AtRestEncryptionConfiguration"]
    if "s3_mode" in path_value:
        at_rest["S3EncryptionConfiguration"]["EncryptionMode"] = path_value["s3_mode"]
    if path_value.get("drop_kms_key"):
        at_rest["S3EncryptionConfiguration"]["EncryptionMode"] = "SSE-KMS"
    return cfg


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSecurityConfiguration rejects an unknown EncryptionMode and SSE-KMS without AwsKmsKey
    with InvalidRequestException and AWS's exact messages, persists neither, and then accepts the
    valid payload by that name."""
    emr = ctx.client("emr")
    name = ctx.unique_name("emr-secconf-semantic-")

    def _cleanup() -> None:
        try:
            emr.delete_security_configuration(Name=name)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "InvalidRequestException"
                and "does not exist" in err.get("Message", "")
            ):
                raise

    ctx.on_cleanup(_cleanup)  # registered before the name is used anywhere

    breaks = [
        (
            "an unmodelled EncryptionMode",
            _mutated(s3_mode="SSE-XYZ"),
            "Invalid security configuration; instance value (SSE-XYZ) is not allowed; "
            "allowed values: [SSE-S3, SSE-KMS, CSE-KMS, CSE-Custom].",
        ),
        (
            "SSE-KMS with no AwsKmsKey",
            _mutated(drop_kms_key=True),
            "Invalid security configuration; AwsKmsKey are required for 'SSE-KMS' or 'CSE-KMS' EncryptionMode.",
        ),
    ]

    for description, bad, expected_message in breaks:
        code, message = _error_stable(
            lambda bad=bad: emr.create_security_configuration(
                Name=name, SecurityConfiguration=json.dumps(bad)
            )
        )
        assert code == EXPECTED_CODE, (
            f"{description} must be rejected with {EXPECTED_CODE}, got {code!r} "
            f"({message!r})"
        )
        assert message == expected_message, (
            f"the rejection of {description} must carry the message {expected_message!r}, got "
            f"{message!r}"
        )

        # --- effect absent: nothing was persisted under this name.
        assert name not in _names(emr), (
            f"a configuration rejected for {description} must not appear in "
            f"ListSecurityConfigurations"
        )
        missing_code, missing_message = _error_stable(
            lambda: emr.describe_security_configuration(Name=name)
        )
        assert missing_code == EXPECTED_CODE, (
            f"after a rejected create, DescribeSecurityConfiguration must report "
            f"{EXPECTED_CODE}, got {missing_code!r} — the rejected payload was stored"
        )
        missing_expected = f'Security configuration with name "{name}" does not exist.'
        assert missing_message == missing_expected, (
            f"expected the message {missing_expected!r}, got {missing_message!r}"
        )

    # --- control: the SAME name with the unmutated payload succeeds, so the rejections
    # were about the one mutated leaf and the name was never consumed.
    created = _create_stable(emr, name, json.dumps(VALID_CONFIG))
    assert created["Name"] == name, (
        f"the create response must echo the name, got {created.get('Name')!r}"
    )

    described = emr.describe_security_configuration(Name=name)
    assert described["Name"] == name, f"unexpected describe response {described!r}"
    stored = json.loads(described["SecurityConfiguration"])
    # Every submitted encryption setting must come back with the value it was given.
    _contains(stored, VALID_CONFIG)
    assert name in _names(emr), (
        "the accepted configuration must appear in ListSecurityConfigurations"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
