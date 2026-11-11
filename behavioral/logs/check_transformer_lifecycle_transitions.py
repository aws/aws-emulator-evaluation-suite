"""transformer-lifecycle-transitions."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transformer-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutTransformer attaches a transformer to a log group retrievable via
    GetTransformer and exercisable via TestTransformer; DeleteTransformer detaches it."""
    logs = ctx.client("logs")
    log_group_name, _ = _create_log_group(ctx)

    # Real AWS requires a transformer config to begin with a parser processor
    # (e.g. parseJSON) before any enrichment processors such as addKeys.
    transformer_config = [
        {"parseJSON": {}},
        {
            "addKeys": {
                "entries": [
                    {"key": "sim2real_marker", "value": "behavioral-check", "overwriteIfExists": True}
                ]
            }
        },
    ]

    logs.put_transformer(logGroupIdentifier=log_group_name, transformerConfig=transformer_config)
    ctx.on_cleanup(
        lambda: _safe_call(lambda: logs.delete_transformer(logGroupIdentifier=log_group_name))
    )

    got = logs.get_transformer(logGroupIdentifier=log_group_name)
    got_config = got["transformerConfig"]
    assert got_config[0]["parseJSON"] == {}, f"expected first processor parseJSON:{{}}, got {got_config[0]!r}"
    got_entry = got_config[1]["addKeys"]["entries"][0]
    assert got_entry["key"] == "sim2real_marker", f"expected addKeys key sim2real_marker, got {got_entry!r}"

    test_resp = logs.test_transformer(
        transformerConfig=transformer_config,
        logEventMessages=['{"existing": "value"}'],
    )
    transformed_message = test_resp["transformedLogs"][0]["transformedEventMessage"]
    transformed = json.loads(transformed_message)
    assert transformed.get("existing") == "value", (
        f"expected parseJSON to preserve original field existing:value, got {transformed!r}"
    )
    assert transformed.get("sim2real_marker") == "behavioral-check", (
        f"expected addKeys to add sim2real_marker:behavioral-check exactly, got {transformed!r}"
    )

    logs.delete_transformer(logGroupIdentifier=log_group_name)
    _wait_for_transformer_removed(logs, log_group_name)

    try:
        logs.delete_transformer(logGroupIdentifier=log_group_name)
        raise AssertionError("expected a second DeleteTransformer on the same log group to fail")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException deleting an "
            f"already-deleted transformer, got {code}"
        )
        message = e.response["Error"].get("Message")
        assert message == (
            f"Transformer does not exist on log group '{log_group_name}'"
        ), (
            f"unexpected message deleting an already-deleted transformer: {message!r}"
        )


def _safe_call(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_for_transformer_removed(logs_client, log_group_name: str, timeout_s: float = 30.0, interval_s: float = 2.0) -> None:
    """After DeleteTransformer, real AWS does not necessarily raise
    ResourceNotFoundException from GetTransformer (the log group itself
    still exists) -- instead the response simply no longer carries a
    transformerConfig. Poll for either outcome."""
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        try:
            resp = logs_client.get_transformer(logGroupIdentifier=log_group_name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        config = resp.get("transformerConfig")
        if not config:
            return
        last = config
        time.sleep(interval_s)
    raise AssertionError(f"expected transformer to be removed, still present: {last!r}")


def _create_log_group(ctx) -> tuple[str, str]:
    logs_client = ctx.client("logs")
    name = ctx.unique_name("sim2real-logs-lg-")
    logs_client.create_log_group(logGroupName=name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs_client.delete_log_group(logGroupName=name))
    arn = logs_client.describe_log_groups(logGroupNamePrefix=name)["logGroups"][0]["arn"]
    return name, arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
