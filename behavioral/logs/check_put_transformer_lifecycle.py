"""put-transformer-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


CHECK = "put-transformer-lifecycle"
GROUP = 'transformers'
SERVICES = ['logs']


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutTransformer stores a config GetTransformer returns verbatim, TestTransformer applies it to a
    sample message, and after DeleteTransformer GetTransformer returns no config.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-transformer-")
    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    ctx.on_cleanup(lambda _n=group: svc.put_log_group_deletion_protection(logGroupIdentifier=_n, deletionProtectionEnabled=False))

    config = [{"parseJSON": {}}, {"addKeys": {"entries": [{"key": "processed", "value": "true"}]}}]
    svc.put_transformer(logGroupIdentifier=group, transformerConfig=config)

    got = svc.get_transformer(logGroupIdentifier=group)
    got_config = got["transformerConfig"]
    assert got_config[0] == {"parseJSON": {}}, f"unexpected first processor: {got_config[0]!r}"
    add_entries = got_config[1]["addKeys"]["entries"]
    assert add_entries[0]["key"] == "processed" and add_entries[0]["value"] == "true", (
        f"unexpected addKeys entry: {add_entries!r}"
    )

    sample = json.dumps({"foo": "bar"})
    test_resp = svc.test_transformer(transformerConfig=config, logEventMessages=[sample])
    transformed = json.loads(test_resp["transformedLogs"][0]["transformedEventMessage"])
    assert transformed.get("processed") == "true", f"TestTransformer did not apply addKeys: {transformed!r}"
    assert transformed.get("foo") == "bar", f"original field lost by TestTransformer: {transformed!r}"

    svc.delete_transformer(logGroupIdentifier=group)

    def _post_delete_transformer():
        try:
            return ("ok", svc.get_transformer(logGroupIdentifier=group))
        except ClientError as exc:
            return (exc.response.get("Error", {}).get("Code"), None)

    final_code, final_resp = _poll_until(
        _post_delete_transformer,
        lambda t: t[0] == "ResourceNotFoundException" or (t[0] == "ok" and not t[1].get("transformerConfig")),
        timeout_s=30,
        interval_s=2.0,
        description="transformer removed (404 or empty transformerConfig)",
    )
    if final_code != "ResourceNotFoundException":
        assert not final_resp.get("transformerConfig"), f"transformer still present after delete: {final_resp!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
