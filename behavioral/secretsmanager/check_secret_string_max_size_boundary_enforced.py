"""secret-string-max-size-boundary-enforced."""
from __future__ import annotations

import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# ForceDeleteWithoutRecovery: DeleteSecret's minimum recovery window is 7 days and a
# secret pending deletion still bills.

MAX_SECRET_BYTES = 65536


def _reap_secret(sm, secret_id, *, timeout_s=60.0, interval_s=2.0):
    """Irreversibly destroy a secret this check minted, then confirm it is gone."""
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sm.describe_secret(SecretId=secret_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"secret {secret_id} still present {timeout_s}s after "
                f"ForceDeleteWithoutRecovery; it bills $0.40/month until reaped"
            )
        time.sleep(interval_s)


def _create_secret(sm, ctx, name, **kwargs):
    """Create a secret, register its reaping teardown, and return the raw response."""
    resp = sm.create_secret(Name=name, **kwargs)
    ctx.on_cleanup(lambda: _reap_secret(sm, resp["ARN"]))
    return resp


def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be refused, but it SUCCEEDED and returned {result!r}")


def _digest(text):
    """Short digest for diagnostics -- never put secret material in an assert message."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _filler(nbytes):
    """Exactly nbytes of self-labelling ASCII, so byte length == character length."""
    unit = "sim2real-not-a-real-secret-"
    return (unit * (nbytes // len(unit) + 1))[:nbytes]


CHECK = "secret-string-max-size-boundary-enforced"
GROUP = 'error-semantics'
SERVICES = ['secretsmanager']


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A 65536-byte SecretString is accepted and a 65537-byte one is refused with
    ValidationException, leaving the stored version untouched; the service enforces this ceiling.
    """
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-maxsize-")

    at_limit = _filler(MAX_SECRET_BYTES)
    assert len(at_limit.encode("utf-8")) == MAX_SECRET_BYTES

    created = _create_secret(
        sm, ctx, name, SecretString=at_limit,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    arn = created["ARN"]
    v1 = created["VersionId"]

    # Positive control: the value exactly at the ceiling round-trips intact.
    got = sm.get_secret_value(SecretId=arn)
    assert got["ARN"] == arn, f"read resolved a different secret: {got['ARN']} != {arn}"
    stored = got["SecretString"]
    assert len(stored.encode("utf-8")) == MAX_SECRET_BYTES, (
        f"a {MAX_SECRET_BYTES}-byte value must not be truncated; stored "
        f"{len(stored.encode('utf-8'))} bytes"
    )
    assert _digest(stored) == _digest(at_limit), (
        f"the at-limit value must round-trip intact; sha256 {_digest(stored)} "
        f"!= {_digest(at_limit)}"
    )

    # One byte over the ceiling; botocore does not validate length.max client-side, so the
    # service must refuse it (ValidationException is not in the modeled error list).
    over_limit = at_limit + "x"
    assert len(over_limit.encode("utf-8")) == MAX_SECRET_BYTES + 1
    code, message = _error_code(lambda: sm.put_secret_value(SecretId=arn, SecretString=over_limit))
    assert code == "ValidationException", (
        f"a {MAX_SECRET_BYTES + 1}-byte SecretString exceeds the documented "
        f"{MAX_SECRET_BYTES}-byte ceiling and must be refused, got {code}"
    )
    expected_message = (
        "1 validation error detected: Value at 'secretString' failed to satisfy constraint: "
        f"Member must have length less than or equal to {MAX_SECRET_BYTES}"
    )
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # Effect absent: no new version, AWSCURRENT unmoved, stored bytes unchanged.
    desc = sm.describe_secret(SecretId=arn)
    stage_map = desc["VersionIdsToStages"]
    assert set(stage_map) == {v1}, (
        f"the refused write must not mint a version; VersionIdsToStages was {stage_map}"
    )
    assert set(stage_map[v1]) == {"AWSCURRENT"}, (
        f"v1 must still hold exactly AWSCURRENT, got {stage_map[v1]}"
    )
    after = sm.get_secret_value(SecretId=arn)
    assert after["VersionId"] == v1, (
        f"AWSCURRENT must still resolve to {v1}, got {after['VersionId']}"
    )
    assert _digest(after["SecretString"]) == _digest(at_limit), (
        "the stored value must be byte-identical after the refused oversized write; "
        f"sha256 {_digest(after['SecretString'])} != {_digest(at_limit)}"
    )

    # Control: the secret is still writable, so the refusal was about the payload
    # size and not about the secret having been wedged.
    small = "sim2real-not-a-real-secret-after-refusal"
    v2 = sm.put_secret_value(SecretId=arn, SecretString=small)["VersionId"]
    assert v2 != v1
    final = sm.get_secret_value(SecretId=arn)
    assert final["VersionId"] == v2
    assert final["SecretString"] == small


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
