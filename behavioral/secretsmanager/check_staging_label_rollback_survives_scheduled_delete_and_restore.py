"""staging-label-rollback-survives-scheduled-delete-and-restore."""

from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "staging-label-rollback-survives-scheduled-delete-and-restore"
GROUP = "state-machine"
SERVICES = ["secretsmanager"]

_SUCCEEDED = "<call succeeded>"


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
    """UpdateSecret writes a new current version; moving AWSCURRENT back to the first version rolls
    the value back and swaps AWSPREVIOUS; a move that omits the current holder is refused; the
    rolled-back value, not the last written one, survives delete and restore."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-rollback-secret-")
    v1, v2 = '{"password":"first-ü"}', '{"password":"second"}'
    t1, t2 = str(uuid.uuid4()), str(uuid.uuid4())
    arn = sm.create_secret(
        Name=name,
        SecretString=v1,
        ClientRequestToken=t1,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["ARN"]

    def _cleanup():
        try:
            sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True)
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    updated = sm.update_secret(
        SecretId=arn, SecretString=v2, ClientRequestToken=t2, Description="rotated by hand"
    )
    assert updated["VersionId"] == t2, (
        f"UpdateSecret VersionId {updated.get('VersionId')!r}, expected the token sent"
    )
    want = {t2: ["AWSCURRENT"], t1: ["AWSPREVIOUS"]}
    got = _settled_stages(sm, arn, want)
    assert got == want, f"after UpdateSecret stages {got!r}"
    assert sm.describe_secret(SecretId=arn)["Description"] == "rotated by hand", (
        "UpdateSecret Description not stored"
    )

    # A move of AWSCURRENT that does not name the version holding it is refused and changes nothing.
    refused = _error(
        lambda: sm.update_secret_version_stage(
            SecretId=arn, VersionStage="AWSCURRENT", MoveToVersionId=t1
        )
    )
    _assert_error(
        refused,
        (
            "InvalidParameterException",
            f"The parameter RemoveFromVersionId can't be empty. Staging label AWSCURRENT is currently attached to version "
            f"{t2}, so you must explicitly reference that version in RemoveFromVersionId.",
        ),
        "UpdateSecretVersionStage without RemoveFromVersionId",
    )
    assert sm.get_secret_value(SecretId=arn)["SecretString"] == v2, (
        "the refused move changed the current value"
    )

    sm.update_secret_version_stage(
        SecretId=arn, VersionStage="AWSCURRENT", MoveToVersionId=t1, RemoveFromVersionId=t2
    )
    current = sm.get_secret_value(SecretId=arn)
    assert (current["VersionId"], current["SecretString"]) == (t1, v1), (
        f"after the rollback the current version is {current['VersionId']!r} reading {current['SecretString']!r}, "
        f"expected the first version reading {v1!r}"
    )
    want = {t1: ["AWSCURRENT"], t2: ["AWSPREVIOUS"]}
    got = _settled_stages(sm, arn, want)
    assert got == want, f"after the rollback stages {got!r}"
    previous = sm.get_secret_value(SecretId=arn, VersionStage="AWSPREVIOUS")["SecretString"]
    assert previous == v2, f"AWSPREVIOUS reads {previous!r} after the rollback, expected {v2!r}"

    sm.delete_secret(SecretId=arn, RecoveryWindowInDays=7)
    _poll_until(
        lambda: sm.describe_secret(SecretId=arn),
        lambda d: d.get("DeletedDate") is not None,
        timeout_s=30.0,
    )
    sm.restore_secret(SecretId=arn)
    _poll_until(
        lambda: sm.describe_secret(SecretId=arn),
        lambda d: d.get("DeletedDate") is None,
        timeout_s=30.0,
    )
    restored = sm.get_secret_value(SecretId=arn)
    assert (restored["VersionId"], restored["SecretString"]) == (t1, v1), (
        f"after restore the current version is {restored['VersionId']!r} reading {restored['SecretString']!r}, "
        f"expected the rolled-back first version"
    )
    want = {t1: ["AWSCURRENT"], t2: ["AWSPREVIOUS"]}
    got = _settled_stages(sm, arn, want)
    assert got == want, f"after restore stages {got!r}"

    sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True)
    gone = _poll_until(
        lambda: _try(lambda: sm.describe_secret(SecretId=arn)),
        lambda r: r["Error"]["Code"] == "ResourceNotFoundException",
        timeout_s=30.0,
    )
    not_found = ("ResourceNotFoundException", "Secrets Manager can't find the specified secret.")
    _assert_error(gone, not_found, "DescribeSecret post-force-delete")
    _assert_error(
        _error(lambda: sm.get_secret_value(SecretId=arn)),
        not_found,
        "GetSecretValue post-force-delete",
    )
    _assert_error(
        _error(
            lambda: sm.update_secret_version_stage(
                SecretId=arn, VersionStage="AWSCURRENT", MoveToVersionId=t2, RemoveFromVersionId=t1
            )
        ),
        not_found,
        "UpdateSecretVersionStage post-force-delete",
    )


def _settled_stages(sm, arn, want):
    """The labelled versions once they read as want, or the last read at the bound: a staging
    change is eventually consistent for DescribeSecret."""
    return _poll_until(
        lambda: _stages(sm, arn), lambda got: got == want, timeout_s=30.0, raise_on_timeout=False
    )


def _stages(sm, arn):
    """The secret's labelled versions as {VersionId: stages}."""
    return {k: v for k, v in sm.describe_secret(SecretId=arn)["VersionIdsToStages"].items() if v}


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


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.5, raise_on_timeout=True):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            if not raise_on_timeout:
                return result
            raise AssertionError(f"condition not met within {timeout_s}s, last value={result!r}")
        time.sleep(interval_s)
        result = probe()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
