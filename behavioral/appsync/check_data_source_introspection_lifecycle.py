"""data-source-introspection-lifecycle."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "data-source-introspection-lifecycle"
GROUP = "state-machine"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartDataSourceIntrospection against a well-formed but nonexistent RDS Data API target creates a
    job that GetDataSourceIntrospection resolves to a terminal state, and an unknown id is not found."""
    appsync = ctx.client("appsync")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region

    bogus_cluster = ctx.unique_name("sim2real-appsync-nonexistent-cluster-")
    bogus_secret = ctx.unique_name("sim2real-appsync-nonexistent-secret-")
    rds_config = {
        "databaseName": "sim2real_missing_db",
        "resourceArn": f"arn:aws:rds:{region}:{account_id}:cluster:{bogus_cluster}",
        "secretArn": f"arn:aws:secretsmanager:{region}:{account_id}:secret:{bogus_secret}",
    }

    # AWS accepts the job and fails it asynchronously.
    started = appsync.start_data_source_introspection(rdsDataApiConfig=rds_config)
    introspection_id = started["introspectionId"]
    assert started.get("introspectionStatus") in ("PROCESSING", "FAILED"), (
        f"unexpected initial introspectionStatus: {started.get('introspectionStatus')!r}"
    )

    def _probe():
        return appsync.get_data_source_introspection(introspectionId=introspection_id)

    final = _poll_until(
        _probe,
        lambda r: r["introspectionStatus"] in ("SUCCESS", "FAILED"),
        timeout_s=120,
        interval_s=5,
    )
    outcome = (final["introspectionStatus"], final.get("introspectionStatusDetail"))
    expected = ("FAILED", "RDS cluster was not found for supplied resource arn.")
    assert outcome == expected, (
        "StartDataSourceIntrospection against a nonexistent RDS cluster/secret must resolve to "
        f"{expected}, got {outcome}"
    )

    # An unknown introspectionId must never resolve to stale/fabricated data.
    bogus_introspection_id = ctx.unique_name("sim2real-appsync-bogus-introspection-")
    code, message = _error(
        lambda: appsync.get_data_source_introspection(introspectionId=bogus_introspection_id)
    )
    assert code == "NotFoundException", (
        "expected GetDataSourceIntrospection with an unknown introspectionId to be "
        f"NotFoundException, got {code!r}"
    )
    expected = "No introspection was found that matches the supplied ID."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn) -> tuple:
    """Call fn(); return its (error code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last value={result!r}")
        time.sleep(interval_s)
        result = probe()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
