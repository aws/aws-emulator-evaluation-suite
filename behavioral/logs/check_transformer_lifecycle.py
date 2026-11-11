"""transformer-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "transformer-lifecycle"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutTransformer attaches a transformer retrievable via GetTransformer and
    removable via DeleteTransformer; once removed, GetTransformer reports
    ResourceNotFoundException again."""
    logs = ctx.client("logs")
    log_group_name = ctx.unique_name("sim2real-behav-xform-")
    logs.create_log_group(
        logGroupName=log_group_name,
        logGroupClass="STANDARD",
        tags={"Sim2RealOwner": "behavioral-suite"},
    )
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))

    # A freshly created log group normally has no transformer, and
    # GetTransformer reports ResourceNotFoundException for that. But if this
    # account happens to have an account-level transformer policy in effect,
    # a brand-new log group inherits that account-level config instead, and
    # GetTransformer succeeds with it. Capture whichever baseline applies so
    # the lifecycle assertions below verify the mutation and its reversal
    # rather than hard-coding an assumption about a shared account's global
    # policy state.
    baseline_state = _transformer_state(logs, log_group_name)

    transformer_config = [
        {"parseJSON": {}},
        {
            "addKeys": {
                "entries": [{"key": "metadata.transformed_by", "value": "sim2real-behavioral"}]
            }
        },
    ]
    logs.put_transformer(
        logGroupIdentifier=log_group_name, transformerConfig=transformer_config
    )

    got = logs.get_transformer(logGroupIdentifier=log_group_name)
    assert got["logGroupIdentifier"] in (log_group_name,) or log_group_name in got["logGroupIdentifier"]
    assert got["transformerConfig"][0]["parseJSON"] == {}
    add_keys = got["transformerConfig"][1]["addKeys"]["entries"]
    assert any(
        e["key"] == "metadata.transformed_by" and e["value"] == "sim2real-behavioral"
        for e in add_keys
    )

    logs.delete_transformer(logGroupIdentifier=log_group_name)

    _wait_for_transformer_state(
        logs, log_group_name, baseline_state, timeout_s=30.0, interval_s=2.0
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    return None


def _transformer_state(logs, log_group_name):
    """Return a comparable snapshot of GetTransformer's outcome: either the
    error code raised (e.g. "ResourceNotFoundException" when no transformer
    applies at all), or the transformerConfig of whatever transformer is
    currently in effect (log-group level or inherited account level)."""
    from botocore.exceptions import ClientError

    try:
        resp = logs.get_transformer(logGroupIdentifier=log_group_name)
    except ClientError as exc:
        return ("error", exc.response["Error"]["Code"])
    return ("ok", resp.get("transformerConfig"))


def _wait_for_transformer_state(logs, log_group_name, expected_state, *, timeout_s, interval_s):
    """DeleteTransformer's removal is not guaranteed to be immediately visible to
    GetTransformer on real AWS. Poll for the log group's state to revert to its
    pre-PutTransformer baseline within a bounded window, raising with the last
    observed state if it never does."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = _transformer_state(logs, log_group_name)
        if last == expected_state:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"transformer state after DeleteTransformer did not revert to the log "
                f"group's pre-PutTransformer baseline ({expected_state!r}) within "
                f"{timeout_s}s; last observed {last!r}"
            )
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
