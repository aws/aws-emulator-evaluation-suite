"""transformer-lifecycle-put-get-delete."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "transformer-lifecycle-put-get-delete"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutTransformer attaches a transformer GetTransformer returns with its addKeys entry, and after
    DeleteTransformer GetTransformer reports ResourceNotFoundException or an empty config.
    """
    logs = ctx.client("logs")
    log_group_name = ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=log_group_name)
    ctx.on_cleanup(lambda: _ignore_notfound(lambda: logs.delete_log_group(logGroupName=log_group_name)))
    ctx.on_cleanup(
        lambda: _ignore_notfound(lambda: logs.delete_transformer(logGroupIdentifier=log_group_name))
    )

    transformer_config = [
        {"parseJSON": {}},
        {"addKeys": {"entries": [{"key": "sim2real_marker", "value": "behav-check", "overwriteIfExists": True}]}},
    ]
    logs.put_transformer(logGroupIdentifier=log_group_name, transformerConfig=transformer_config)

    got = logs.get_transformer(logGroupIdentifier=log_group_name)
    assert log_group_name in got.get("logGroupIdentifier", ""), (
        f"expected logGroupIdentifier to reference {log_group_name}, got {got.get('logGroupIdentifier')}"
    )
    got_config = got["transformerConfig"]
    assert len(got_config) == 2 and "addKeys" in got_config[1], f"unexpected transformerConfig: {got_config}"
    entries = got_config[1]["addKeys"]["entries"]
    assert any(
        e["key"] == "sim2real_marker" and e["value"] == "behav-check" for e in entries
    ), f"expected addKeys entry to round-trip, got {entries}"

    logs.delete_transformer(logGroupIdentifier=log_group_name)

    kind, value = _poll_until_transformer_removed(
        lambda: logs.get_transformer(logGroupIdentifier=log_group_name),
    )
    removed = (kind == "error" and value == "ResourceNotFoundException") or (
        kind == "config" and not value
    )
    assert removed, (
        "expected GetTransformer after delete to either raise ResourceNotFoundException or "
        f"report an empty transformerConfig, got {kind}={value!r}"
    )


def _error_code(fn):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        resp = getattr(exc, "response", None)
        if isinstance(resp, dict):
            return resp.get("Error", {}).get("Code")
        raise
    return None


def _poll_until_transformer_removed(fn, timeout: float = 30.0, interval: float = 2.0):
    """DeleteTransformer's removal is not always immediately visible to GetTransformer, and on
    real AWS the removal can surface either as a ResourceNotFoundException or as GetTransformer
    continuing to succeed with an empty transformerConfig. Poll for either signal within a
    bounded window rather than assuming a single specific error code, and return
    (kind, value) where kind is "error" (value = error code) or "config" (value =
    transformerConfig, possibly empty/None)."""
    import time

    deadline = time.monotonic() + timeout
    last_result = (None, None)
    while True:
        try:
            resp = fn()
            config = resp.get("transformerConfig")
            last_result = ("config", config)
            if not config:
                return last_result
        except Exception as exc:  # noqa: BLE001
            resp_err = getattr(exc, "response", None)
            code = resp_err.get("Error", {}).get("Code") if isinstance(resp_err, dict) else None
            if code is None:
                raise
            last_result = ("error", code)
            if code == "ResourceNotFoundException":
                return last_result
        if time.monotonic() >= deadline:
            return last_result
        time.sleep(interval)


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
