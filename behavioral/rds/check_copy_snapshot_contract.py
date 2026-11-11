"""copy-snapshot-contract."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "copy-snapshot-contract"
GROUP = 'snapshots'
SERVICES = ['rds']

ERR_DB_SNAPSHOT_NOT_FOUND = "DBSnapshotNotFound"
ERR_INVALID_PARAMETER_VALUE = "InvalidParameterValue"


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected CopyDBSnapshot to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CopyDBSnapshot from an unknown source snapshot is rejected with DBSnapshotNotFound and a
    malformed request with InvalidParameterValue, each with its exact message, so the target tells
    absence from bad format."""
    rds = ctx.client("rds")
    bogus_src = ctx.unique_name("sim2real-behav-snap-missing-")
    code, message = _error(
        lambda: rds.copy_db_snapshot(
            SourceDBSnapshotIdentifier=bogus_src,
            TargetDBSnapshotIdentifier=ctx.unique_name("sim2real-behav-snap-tgt-"),
        )
    )
    assert code == ERR_DB_SNAPSHOT_NOT_FOUND, f"expected {ERR_DB_SNAPSHOT_NOT_FOUND}, got {code!r}"
    expected = f"Requested snapshot {bogus_src} not found in source region {ctx.region}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    malformed_src = "1-" + ctx.unique_name("invalid-leading-digit-")
    code_malformed, message_malformed = _error(
        lambda: rds.copy_db_snapshot(
            SourceDBSnapshotIdentifier=malformed_src,
            TargetDBSnapshotIdentifier=ctx.unique_name("sim2real-behav-snap-tgt-"),
        )
    )
    assert code_malformed == ERR_INVALID_PARAMETER_VALUE, (
        f"expected {ERR_INVALID_PARAMETER_VALUE} for a malformed source identifier, "
        f"got {code_malformed!r}"
    )
    # AWS's message carries two spaces after the colon.
    expected_malformed = f"Invalid snapshot identifier:  {malformed_src}"
    assert message_malformed == expected_malformed, (
        f"expected message {expected_malformed!r}, got {message_malformed!r}"
    )
    assert code_malformed != code, (
        "a malformed source and a well-formed-but-absent source must not collapse "
        f"onto the same error code ({code_malformed!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
