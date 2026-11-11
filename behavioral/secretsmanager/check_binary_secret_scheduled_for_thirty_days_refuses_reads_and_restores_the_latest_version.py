"""binary-secret-scheduled-for-thirty-days-refuses-reads-and-restores-the-latest-version."""

from __future__ import annotations

import datetime as _dt
import secrets
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "binary-secret-scheduled-for-thirty-days-refuses-reads-and-restores-the-latest-version"
GROUP = "state-machine"
SERVICES = ["secretsmanager"]

_SUCCEEDED = "<call succeeded>"
_WINDOW_DAYS = 30
_MARKED = "You can't perform this operation on the secret because it was marked for deletion."


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c4",
    "concern:data-plane",
    "concern:negative-classes",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Three binary versions keep their bytes and stages (current, previous, unlabelled); a 30-day
    scheduled deletion reports its date and refuses reads and writes; restore brings back the
    third version's bytes, and force delete makes the secret not found."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-binary-secret-")
    values = [b"\x00" + secrets.token_bytes(63), secrets.token_bytes(1), secrets.token_bytes(4096)]
    tokens = [str(uuid.uuid4()) for _ in values]

    created = sm.create_secret(
        Name=name,
        SecretBinary=values[0],
        ClientRequestToken=tokens[0],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    arn = created["ARN"]

    def _cleanup():
        try:
            sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True)
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    assert created["VersionId"] == tokens[0], (
        f"CreateSecret VersionId {created['VersionId']!r}, expected the token sent"
    )
    for value, token in zip(values[1:], tokens[1:], strict=True):
        put = sm.put_secret_value(SecretId=arn, SecretBinary=value, ClientRequestToken=token)
        assert (put["VersionId"], put["VersionStages"]) == (token, ["AWSCURRENT"]), (
            f"PutSecretValue answered {(put['VersionId'], put['VersionStages'])!r}, expected the token and ['AWSCURRENT']"
        )

    current = sm.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")
    previous = sm.get_secret_value(SecretId=arn, VersionStage="AWSPREVIOUS")
    first = sm.get_secret_value(SecretId=arn, VersionId=tokens[0])
    got = [
        (r["VersionId"], r["SecretBinary"], "SecretString" in r) for r in (current, previous, first)
    ]
    expected = [
        (tokens[2], values[2], False),
        (tokens[1], values[1], False),
        (tokens[0], values[0], False),
    ]
    assert got == expected, (
        f"current/previous/first read (VersionId, bytes, has SecretString) "
        f"{[(v, len(b), s) for v, b, s in got]!r}, expected the third, second and first versions' bytes and no string"
    )
    assert not first.get("VersionStages"), (
        f"the first version keeps stages {first.get('VersionStages')!r}, expected none"
    )
    stages = {k: v for k, v in sm.describe_secret(SecretId=arn)["VersionIdsToStages"].items() if v}
    assert stages == {tokens[2]: ["AWSCURRENT"], tokens[1]: ["AWSPREVIOUS"]}, (
        f"DescribeSecret labelled versions {stages!r}, expected the third AWSCURRENT and the second AWSPREVIOUS"
    )

    deleted = sm.delete_secret(SecretId=arn, RecoveryWindowInDays=_WINDOW_DAYS)
    days_out = (
        deleted["DeletionDate"] - _dt.datetime.now(_dt.timezone.utc)
    ).total_seconds() / 86400
    assert _WINDOW_DAYS - 1 <= days_out <= _WINDOW_DAYS + 1, (
        f"DeleteSecret DeletionDate is {days_out:.2f} days out, expected {_WINDOW_DAYS} days +/- 1"
    )
    refused = _poll_until(
        lambda: _try(lambda: sm.get_secret_value(SecretId=arn)),
        lambda r: r["Error"]["Code"] != _SUCCEEDED,
        timeout_s=30.0,
    )
    _assert_error(
        refused, ("InvalidRequestException", _MARKED), "GetSecretValue while scheduled for deletion"
    )
    _assert_error(
        _error(lambda: sm.put_secret_value(SecretId=arn, SecretBinary=b"x")),
        ("InvalidRequestException", _MARKED),
        "PutSecretValue while scheduled for deletion",
    )

    sm.restore_secret(SecretId=arn)
    described = _poll_until(
        lambda: sm.describe_secret(SecretId=arn),
        lambda d: d.get("DeletedDate") is None,
        timeout_s=30.0,
    )
    assert described.get("DeletedDate") is None, (
        f"DeletedDate not cleared after restore: {described!r}"
    )
    restored = sm.get_secret_value(SecretId=arn)
    assert (restored["VersionId"], restored["SecretBinary"]) == (tokens[2], values[2]), (
        f"after restore the current version is {restored['VersionId']!r} with {len(restored['SecretBinary'])} bytes, "
        f"expected the third version's {len(values[2])} bytes"
    )

    sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True)
    gone = _poll_until(
        lambda: _try(lambda: sm.describe_secret(SecretId=arn)),
        lambda r: r["Error"]["Code"] == "ResourceNotFoundException",
        timeout_s=30.0,
    )
    not_found = ("ResourceNotFoundException", "Secrets Manager can't find the specified secret.")
    _assert_error(gone, not_found, "DescribeSecret post-force-delete")
    _assert_error(
        _error(lambda: sm.restore_secret(SecretId=arn)),
        not_found,
        "RestoreSecret post-force-delete",
    )


def _error(fn):
    """Call fn(), which must fail; return its error response. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response
    raise AssertionError(
        f"expected the call to be refused, but it SUCCEEDED and returned {result!r}"
    )


def _try(fn):
    """A poll probe: the error response of fn(), or a Code no service returns on success."""
    try:
        result = fn()
    except ClientError as err:
        return err.response
    return {"Error": {"Code": _SUCCEEDED, "Message": repr(result)}}


def _assert_error(response, expected, what):
    """The response carries exactly the expected (code, message) with an HTTP 4xx."""
    got = (response["Error"]["Code"], response["Error"].get("Message"))
    assert got == expected, f"{what}: expected {expected}, got {got!r}"
    status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert isinstance(status, int) and 400 <= status < 500, (
        f"{what}: expected HTTP 4xx, got {status!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.5):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value={result!r}")
        time.sleep(interval_s)
        result = probe()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
