"""delete-group-nonexistent-resource-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-group-nonexistent-resource-not-found"
GROUP = "error-semantics"
SERVICES = ["synthetics"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteGroup on a nonexistent GroupIdentifier returns ResourceNotFoundException."""
    synth = ctx.client("synthetics")
    missing = ctx.unique_name("sim2real-nogroup-")

    error = _client_error(lambda: synth.delete_group(GroupIdentifier=missing))
    assert error["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {error!r}"
    expected_message = f"Group does not exist: {missing}"
    assert error["Message"] == expected_message, f"expected message {expected_message!r}, got {error['Message']!r}"

    # Positive control: deleting a group that really exists succeeds.
    group_name = ctx.unique_name("sim2real-group-")
    synth.create_group(Name=group_name)
    ctx.on_cleanup(lambda: _safe(lambda: synth.delete_group(GroupIdentifier=group_name)))
    synth.delete_group(GroupIdentifier=group_name)

    gone_message = f"Group does not exist: {group_name}"
    after_error = _client_error(lambda: synth.get_group(GroupIdentifier=group_name))
    assert after_error["Code"] == "ResourceNotFoundException", (
        f"expected the deleted group to be gone, got {after_error!r}"
    )
    assert after_error["Message"] == gone_message, (
        f"expected message {gone_message!r}, got {after_error['Message']!r}"
    )

    # The dead id is not just absent from reads, it is unusable: a further mutation
    # on the same id must still 404, not silently no-op.
    redelete_error = _client_error(lambda: synth.delete_group(GroupIdentifier=group_name))
    assert redelete_error["Code"] == "ResourceNotFoundException", (
        f"expected a repeat delete on the same dead group to still 404, got {redelete_error!r}"
    )
    assert redelete_error["Message"] == gone_message, (
        f"expected message {gone_message!r}, got {redelete_error['Message']!r}"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _client_error(fn) -> dict:
    """Call fn() and return the botocore Error dict (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
