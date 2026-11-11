"""deep-secrets-and-params-restore-secret-preserves-the-whole-staging-map-and-every-version."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-secrets-and-params-restore-secret-preserves-the-whole-staging-map-and-every-version"

GROUP = "deletion"

SERVICES = ["secretsmanager"]

_SCENARIO = "deep-secrets-restore-staging-map"
_CANARY = "sim2real-canary"
_BINSTAGE = "sim2real-binary"
# Every byte value, so a text round-trip, a strip or a re-encode anywhere is visible.
_BLOB = bytes(range(256))
_MARKED_FOR_DELETION_MESSAGE = (
    "You can't perform this operation on the secret because it was marked for deletion."
)


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c4",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """While scheduled for deletion, every value read and write is refused (InvalidRequestException)
    and mints nothing; RestoreSecret brings back the identical staging map (AWSCURRENT,
    AWSPREVIOUS, custom and binary versions) with every version's bytes exact.
    """
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-deep-sm-")

    created = sm.create_secret(
        Name=name,
        SecretString="alpha-original",
        Description="sim2real behavioral check: restore preserves the staging map",
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}, {"Key": "sim2real:managed", "Value": "true"}],
    )
    arn = created["ARN"]
    ctx.on_cleanup(lambda: _reap_secret(sm, arn))
    v_alpha = created["VersionId"]

    v_bravo = sm.put_secret_value(SecretId=arn, SecretString="bravo-current")["VersionId"]
    v_charlie = sm.put_secret_value(
        SecretId=arn, SecretString="charlie-canary", VersionStages=[_CANARY]
    )["VersionId"]
    v_bin = sm.put_secret_value(
        SecretId=arn, SecretBinary=_BLOB, VersionStages=[_BINSTAGE]
    )["VersionId"]

    expected_values = {
        v_alpha: ("SecretString", "alpha-original"),
        v_bravo: ("SecretString", "bravo-current"),
        v_charlie: ("SecretString", "charlie-canary"),
        v_bin: ("SecretBinary", _BLOB),
    }
    before = _normalise(sm.describe_secret(SecretId=arn)["VersionIdsToStages"])
    assert before == {
        v_alpha: ["AWSPREVIOUS"],
        v_bravo: ["AWSCURRENT"],
        v_charlie: [_CANARY],
        v_bin: [_BINSTAGE],
    }, f"baseline staging map is not what the four writes should produce: {before!r}"
    _assert_versions_exact(sm, arn, expected_values, when="before delete")

    # --- schedule deletion ------------------------------------------------------------------
    deleted = sm.delete_secret(SecretId=arn, RecoveryWindowInDays=7)
    assert deleted["ARN"] == arn and deleted.get("DeletionDate") is not None, deleted

    for label, call in (
        ("get_secret_value()", lambda: sm.get_secret_value(SecretId=arn)),
        ("get_secret_value(VersionStage=AWSPREVIOUS)",
         lambda: sm.get_secret_value(SecretId=arn, VersionStage="AWSPREVIOUS")),
        (f"get_secret_value(VersionStage={_CANARY})",
         lambda: sm.get_secret_value(SecretId=arn, VersionStage=_CANARY)),
        ("get_secret_value(VersionId=binary)",
         lambda: sm.get_secret_value(SecretId=arn, VersionId=v_bin)),
        ("put_secret_value", lambda: sm.put_secret_value(SecretId=arn, SecretString="intruder")),
    ):
        code, message = _error(call)
        assert code == "InvalidRequestException", (
            f"{label} on a secret scheduled for deletion must be refused with "
            f"InvalidRequestException, got {code!r}: {message!r}"
        )
        assert message == _MARKED_FOR_DELETION_MESSAGE, (
            f"{label}'s refusal must name the scheduled deletion, got {message!r}"
        )

    # Effect absent: the refused put minted nothing (the version list is still readable).
    during = sorted(
        v["VersionId"]
        for v in sm.list_secret_version_ids(SecretId=arn, IncludeDeprecated=True)["Versions"]
    )
    assert during == sorted(expected_values), (
        f"a refused write on a scheduled secret must not mint a version: {during!r}"
    )

    # --- restore ------------------------------------------------------------------------------
    restored = sm.restore_secret(SecretId=arn)
    assert restored["ARN"] == arn, f"restore must bring back the SAME secret, got {restored!r}"
    # DescribeSecret can briefly still report DeletedDate right after RestoreSecret returns.
    deadline = time.monotonic() + 60.0
    desc = sm.describe_secret(SecretId=arn)
    while desc.get("DeletedDate") is not None and time.monotonic() < deadline:
        time.sleep(2.0)
        desc = sm.describe_secret(SecretId=arn)
    assert desc.get("DeletedDate") is None, f"restore must clear DeletedDate: {desc.get('DeletedDate')!r}"
    after = _normalise(desc["VersionIdsToStages"])
    assert after == before, (
        f"restore must reinstate the identical staging map\n  before={before!r}\n  after ={after!r}"
    )
    _assert_versions_exact(sm, arn, expected_values, when="after restore")

    # Stage reads agree with id reads after restore.
    assert _get(sm, SecretId=arn)["VersionId"] == v_bravo
    prev = _get(sm, SecretId=arn, VersionStage="AWSPREVIOUS")
    assert (prev["VersionId"], prev["SecretString"]) == (v_alpha, "alpha-original"), (
        f"AWSPREVIOUS must resolve the original version byte-exact after restore: {prev!r}"
    )
    canary = _get(sm, SecretId=arn, VersionStage=_CANARY)
    assert (canary["VersionId"], canary["SecretString"]) == (v_charlie, "charlie-canary"), canary
    binary = _get(sm, SecretId=arn, VersionStage=_BINSTAGE)
    assert binary["VersionId"] == v_bin and binary["SecretBinary"] == _BLOB, (
        f"the binary version must survive delete/restore byte-exact; got {len(binary.get('SecretBinary', b''))} "
        f"bytes, first 8 {binary.get('SecretBinary', b'')[:8]!r}"
    )


def _normalise(staged: dict) -> dict:
    return {k: sorted(v) for k, v in staged.items()}


def _assert_versions_exact(sm, arn: str, expected: dict, *, when: str) -> None:
    for version_id, (field, value) in expected.items():
        got = _get(sm, SecretId=arn, VersionId=version_id)
        assert got["VersionId"] == version_id, got
        assert got.get(field) == value, (
            f"{when}: version {version_id} must hold its exact {field}; got "
            f"{got.get(field)!r:.120}"
        )
        other = "SecretBinary" if field == "SecretString" else "SecretString"
        assert other not in got, f"{when}: version {version_id} unexpectedly carries {other}"


def _error(fn, timeout_s: float = 30.0) -> tuple[str, str]:
    """(Error.Code, Error.Message) of a refused call. The scheduled deletion takes a few seconds to
    reach every read path, so a success is retried until the deadline and then raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code", "<no code>"), err.get("Message", "")
        if time.monotonic() >= deadline:
            raise AssertionError(f"the call was expected to be refused but SUCCEEDED: {result!r}")
        time.sleep(2.0)


def _get(sm, *, timeout_s: float = 30.0, **kwargs):
    """GetSecretValue that waits out the few seconds a restore takes to reach every read path."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return sm.get_secret_value(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Message") != _MARKED_FOR_DELETION_MESSAGE or time.monotonic() >= deadline:
                raise
            time.sleep(2.0)


def _reap_secret(sm, secret_id: str, timeout_s: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code in ("ThrottlingException", "InternalServiceError"):
                time.sleep(2.0)
                continue
            teardown_code = exc.response.get("Error", {}).get("Code", "")
            if teardown_code not in ("ResourceNotFoundException",):
                raise RuntimeError(
                    f"delete_secret({secret_id}) failed with {code}: {exc}"
                ) from exc
            return
    raise RuntimeError(f"secret {secret_id} could not be force-deleted within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
