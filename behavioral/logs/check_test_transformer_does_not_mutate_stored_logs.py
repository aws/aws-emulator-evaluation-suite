"""test-transformer-does-not-mutate-stored-logs."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "test-transformer-does-not-mutate-stored-logs"
GROUP = "overly-permissive"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """TestTransformer is a dry run: it never overwrites the log group's persisted transformer
    config, even when tested with a different transformerConfig.
    """
    logs = ctx.client("logs")

    log_group = ctx.unique_name("sim2real-behav-transformer-")
    logs.create_log_group(logGroupName=log_group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))

    transformer_a = [
        {"grok": {"match": "%{GREEDYDATA:message}"}},
        {"addKeys": {"entries": [{"key": "marker", "value": "A", "overwriteIfExists": True}]}},
    ]
    logs.put_transformer(logGroupIdentifier=log_group, transformerConfig=transformer_a)
    ctx.on_cleanup(lambda: _safe_delete_transformer(logs, log_group))

    baseline = logs.get_transformer(logGroupIdentifier=log_group)
    assert baseline["transformerConfig"] == transformer_a, (
        f"expected PutTransformer's config to be readable back verbatim, "
        f"got {baseline['transformerConfig']}"
    )

    transformer_b = [
        {"grok": {"match": "%{GREEDYDATA:message}"}},
        {"addKeys": {"entries": [{"key": "marker", "value": "B", "overwriteIfExists": True}]}},
    ]
    test_resp = logs.test_transformer(
        transformerConfig=transformer_b, logEventMessages=["hello-dry-run"]
    )
    transformed = test_resp["transformedLogs"]
    assert len(transformed) == 1, f"expected exactly one transformed log, got {transformed}"
    assert transformed[0]["eventMessage"] == "hello-dry-run", (
        f"expected the original message echoed back, got {transformed[0]['eventMessage']!r}"
    )
    assert transformed[0]["transformedEventMessage"] != transformed[0]["eventMessage"], (
        "TestTransformer should have applied transformer_b to produce a different message"
    )
    assert '"marker":"B"' in transformed[0]["transformedEventMessage"].replace(" ", ""), (
        f"expected transformer_b's marker=B in dry-run output, got "
        f"{transformed[0]['transformedEventMessage']}"
    )

    after = logs.get_transformer(logGroupIdentifier=log_group)
    assert after["transformerConfig"] == transformer_a, (
        "TestTransformer must not persist/overwrite the log group's real transformer config, "
        f"but GetTransformer now returns {after['transformerConfig']}"
    )
    assert after["lastModifiedTime"] == baseline["lastModifiedTime"], (
        "TestTransformer must not touch lastModifiedTime of the persisted transformer"
    )



def _safe_delete_transformer(logs, log_group: str) -> None:
    try:
        logs.delete_transformer(logGroupIdentifier=log_group)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
