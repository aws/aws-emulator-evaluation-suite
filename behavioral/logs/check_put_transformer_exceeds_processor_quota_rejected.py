"""put-transformer-exceeds-processor-quota-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-transformer-exceeds-processor-quota-rejected"
GROUP = "overly-permissive"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutTransformer accepts 20 processors, refuses 21 with InvalidParameterException and its exact
    validation message, and GetTransformer still returns the 20-processor config.
    """
    logs = ctx.client("logs")
    log_group_name = ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=log_group_name)
    ctx.on_cleanup(lambda: _ignore_notfound(lambda: logs.delete_log_group(logGroupName=log_group_name)))
    ctx.on_cleanup(
        lambda: _ignore_notfound(lambda: logs.delete_transformer(logGroupIdentifier=log_group_name))
    )

    # Positive control: an in-quota transformerConfig is accepted and persisted verbatim. Without
    # this, rejecting the 21-processor config below is indistinguishable from PutTransformer being
    # rejected unconditionally on this log group/account.
    in_quota_config = [
        {"parseJSON": {}},
        {"addKeys": {"entries": [{"key": "control", "value": "present", "overwriteIfExists": True}]}},
    ]
    logs.put_transformer(logGroupIdentifier=log_group_name, transformerConfig=in_quota_config)
    control_resp = logs.get_transformer(logGroupIdentifier=log_group_name)
    assert control_resp.get("transformerConfig") == in_quota_config, (
        f"positive control failed: an in-quota PutTransformer did not persist verbatim, "
        f"got {control_resp.get('transformerConfig')!r}"
    )

    too_many_processors = [{"parseJSON": {}}] + [
        {"addKeys": {"entries": [{"key": f"k{i}", "value": f"v{i}", "overwriteIfExists": True}]}}
        for i in range(20)
    ]

    code, message = _error_code(
        lambda: logs.put_transformer(
            logGroupIdentifier=log_group_name, transformerConfig=too_many_processors
        )
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for a 21-processor transformerConfig (quota is 20), "
        f"got {code}: {message!r}"
    )
    assert message == (
        "1 validation error detected: Value at 'transformerConfig' failed to satisfy constraint: "
        "Member must have length less than or equal to 20"
    ), f"unexpected over-quota PutTransformer message: {message!r}"

    after_resp = logs.get_transformer(logGroupIdentifier=log_group_name)
    assert after_resp.get("transformerConfig") == in_quota_config, (
        "the over-quota PutTransformer must leave the existing transformer config unchanged, "
        f"got {after_resp.get('transformerConfig')!r}"
    )


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        resp = getattr(exc, "response", None)
        if isinstance(resp, dict):
            return resp.get("Error", {}).get("Code"), resp.get("Error", {}).get("Message")
        raise
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
