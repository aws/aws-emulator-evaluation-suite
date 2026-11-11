"""test-transformer-dry-run-does-not-persist."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "test-transformer-dry-run-does-not-persist"
GROUP = "overly-permissive"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestTransformer returns the transformed sample event without persisting the transformer:
    GetTransformer reports none before and after it, while a PutTransformer control is reported.
    """
    logs = ctx.client("logs")
    log_group_name = ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=log_group_name)
    ctx.on_cleanup(lambda: _ignore_notfound(lambda: logs.delete_log_group(logGroupName=log_group_name)))
    ctx.on_cleanup(
        lambda: _ignore_notfound(lambda: logs.delete_transformer(logGroupIdentifier=log_group_name))
    )

    baseline_absent, baseline_detail = _transformer_absent(logs, log_group_name)
    assert baseline_absent, (
        f"expected a fresh log group to have no transformer, got {baseline_detail}"
    )

    control_config = [{"parseJSON": {}}]
    logs.put_transformer(logGroupIdentifier=log_group_name, transformerConfig=control_config)
    control_resp = logs.get_transformer(logGroupIdentifier=log_group_name)
    assert control_resp.get("transformerConfig") == control_config, (
        "positive control failed: expected PutTransformer to make the transformer visible via "
        f"GetTransformer on this log group, got {control_resp.get('transformerConfig')!r}"
    )
    logs.delete_transformer(logGroupIdentifier=log_group_name)
    reset_absent, reset_detail = _poll_until(
        lambda: _transformer_absent(logs, log_group_name),
        lambda t: t[0],
        timeout_s=30.0,
        interval_s=2.0,
        description="transformer removed after DeleteTransformer",
    )
    assert reset_absent, (
        f"expected DeleteTransformer to leave the log group with no persisted transformer, got {reset_detail}"
    )

    transformer_config = [
        {"parseJSON": {}},
        {"addKeys": {"entries": [{"key": "dry_run_marker", "value": "should-not-persist", "overwriteIfExists": True}]}},
    ]
    result = logs.test_transformer(
        transformerConfig=transformer_config,
        logEventMessages=['{"message": "hello dry-run world"}'],
    )
    transformed = result["transformedLogs"]
    assert len(transformed) == 1, f"expected exactly one transformed log, got {transformed}"
    assert (
        transformed[0]["eventMessage"] == '{"message": "hello dry-run world"}'
    ), f"expected original message echoed back, got {transformed[0]}"
    assert "dry_run_marker" in transformed[0]["transformedEventMessage"], (
        f"expected the addKeys processor to apply during the dry run, got {transformed[0]}"
    )

    after_absent, after_detail = _transformer_absent(logs, log_group_name)
    assert after_absent, (
        f"TestTransformer must not persist a transformer; expected no persisted transformer, got {after_detail}"
    )


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s (last={last!r})")


def _transformer_absent(logs, log_group_name: str):
    """Returns (True, detail) if the log group has no persisted transformer, whether that is
    surfaced as a ResourceNotFoundException or as a successful response with an empty
    transformerConfig."""
    try:
        resp = logs.get_transformer(logGroupIdentifier=log_group_name)
    except Exception as exc:  # noqa: BLE001
        resp_body = getattr(exc, "response", None)
        code = resp_body.get("Error", {}).get("Code") if isinstance(resp_body, dict) else None
        if code == "ResourceNotFoundException":
            return True, code
        raise
    config = resp.get("transformerConfig")
    return (not config), f"transformerConfig={config!r}"


def _ignore_notfound(fn) -> None:
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        resp = getattr(exc, "response", None)
        code = resp.get("Error", {}).get("Code") if isinstance(resp, dict) else None
        if code not in ("ResourceNotFoundException", None):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
