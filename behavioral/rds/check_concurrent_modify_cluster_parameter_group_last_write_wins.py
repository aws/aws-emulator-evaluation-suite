"""concurrent-modify-cluster-parameter-group-last-write-wins."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-modify-cluster-parameter-group-last-write-wins"
GROUP = "concurrency"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent ModifyDBClusterParameterGroup writes of one parameter never merge: the stored
    value is exactly one write (the winner's if a racer gets InvalidDBParameterGroupState), it
    is stable across reads, and writing the other value afterwards succeeds."""
    rds = ctx.client("rds")

    versions = rds.describe_db_engine_versions(Engine="aurora-mysql", DefaultOnly=True)[
        "DBEngineVersions"
    ]
    if not versions:
        versions = rds.describe_db_engine_versions(Engine="aurora-mysql")["DBEngineVersions"]
    family = versions[0]["DBParameterGroupFamily"]

    group_name = ctx.unique_name("sim2real-cpg-")
    rds.create_db_cluster_parameter_group(
        DBClusterParameterGroupName=group_name,
        DBParameterGroupFamily=family,
        Description="sim2real concurrency check: last-write-wins",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_cluster_parameter_group(DBClusterParameterGroupName=group_name)
    )

    # "time_zone" is a dynamic (runtime-settable) MySQL/Aurora-MySQL parameter, valid at the
    # cluster-parameter-group level whether or not any cluster is currently attached.
    candidate_values = {"racer-a": "US/Pacific", "racer-b": "US/Eastern"}

    def _modify(value: str):
        return rds.modify_db_cluster_parameter_group(
            DBClusterParameterGroupName=group_name,
            Parameters=[
                {"ParameterName": "time_zone", "ParameterValue": value, "ApplyMethod": "immediate"}
            ],
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = {label: pool.submit(_modify, value) for label, value in candidate_values.items()}
        winners: dict[str, str] = {}
        rejections: dict[str, ClientError] = {}
        for label, fut in futures.items():
            try:
                fut.result()
                winners[label] = candidate_values[label]
            except ClientError as exc:
                rejections[label] = exc

    assert winners and len(winners) + len(rejections) == 2, (
        f"expected at least one concurrent modify to win the lock, "
        f"got winners={sorted(winners)} rejections={sorted(rejections)}"
    )
    for loser_exc in rejections.values():
        error_code = loser_exc.response["Error"]["Code"]
        assert error_code == "InvalidDBParameterGroupState", (
            f"expected the losing concurrent modify to be rejected with "
            f"InvalidDBParameterGroupState, got {error_code!r} ({loser_exc})"
        )
        message = loser_exc.response["Error"]["Message"]
        assert message == "parameters cannot be modified at this time", (
            f"expected message 'parameters cannot be modified at this time', got {message!r}"
        )

    def _current_value() -> str:
        params = []
        paginator = rds.get_paginator("describe_db_cluster_parameters")
        for page in paginator.paginate(DBClusterParameterGroupName=group_name):
            params.extend(page["Parameters"])
        matches = [p for p in params if p["ParameterName"] == "time_zone"]
        assert matches, "time_zone parameter missing from parameter group after modify"
        return matches[0]["ParameterValue"]

    # Poll several times to confirm the resolved value is STABLE (not oscillating between the
    # two writers, which would indicate a corrupted merge rather than a clean single winner).
    final_value = None
    for _ in range(10):
        current = _current_value()
        if final_value is None:
            final_value = current
        elif current != final_value:
            raise AssertionError(
                f"parameter value flickered between reads: {final_value!r} vs {current!r}"
            )
        time.sleep(1)

    if rejections:
        winner_value = next(iter(winners.values()))
        loser_value = candidate_values[next(iter(rejections))]
        assert final_value == winner_value, (
            f"final value {final_value!r} does not match the winning concurrent write "
            f"{winner_value!r} (the rejected racer wrote {loser_value!r})"
        )
    else:
        assert final_value in candidate_values.values(), (
            f"final value {final_value!r} is neither concurrent write "
            f"{sorted(candidate_values.values())} -- a corrupted merge"
        )
        loser_value = next(v for v in candidate_values.values() if v != final_value)

    # Restore: the lock is released once the winning modify has settled, so writing the other
    # racer's value against the now-unlocked group must succeed -- proving any earlier
    # rejection was a transient lock, not a permanent refusal of that value.
    _modify(loser_value)
    restored = _current_value()
    assert restored == loser_value, (
        f"retrying the previously-rejected value {loser_value!r} after the lock cleared "
        f"did not apply; got {restored!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
