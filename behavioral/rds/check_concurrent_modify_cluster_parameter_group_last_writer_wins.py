"""concurrent-modify-cluster-parameter-group-last-writer-wins."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-modify-cluster-parameter-group-last-writer-wins"
GROUP = "concurrency"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent ModifyDBClusterParameterGroup calls setting different values for
    the same parameter converge to exactly one deterministic final value -- never a
    corrupted/merged value and never both values coexisting."""
    rds = ctx.client("rds")
    group_name = ctx.unique_name("sim2real-rds-cpg-")
    family = "aurora-mysql8.0"
    param_name = "innodb_lock_wait_timeout"
    value_a = "45"
    value_b = "90"

    rds.create_db_cluster_parameter_group(
        DBClusterParameterGroupName=group_name,
        DBParameterGroupFamily=family,
        Description="sim2real concurrency test group",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_cluster_parameter_group(DBClusterParameterGroupName=group_name)
    )

    def _set(value):
        # Real RDS answers a genuinely-concurrent modify against the SAME parameter group with
        # InvalidDBParameterGroupState ("parameters cannot be modified at this time") rather than
        # queueing or merging it -- this is the API's own contention resolution, not corruption,
        # so the racer retries on that specific fault until its write lands.
        deadline = time.monotonic() + 30
        while True:
            try:
                return rds.modify_db_cluster_parameter_group(
                    DBClusterParameterGroupName=group_name,
                    Parameters=[
                        {
                            "ParameterName": param_name,
                            "ParameterValue": value,
                            "ApplyMethod": "immediate",
                        }
                    ],
                )
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code != "InvalidDBParameterGroupState" or time.monotonic() > deadline:
                    raise
                time.sleep(1)

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(_set, value_a)
        fut_b = pool.submit(_set, value_b)
        fut_a.result()
        fut_b.result()

    final_value = _poll_for_param(
        rds, group_name, param_name, {value_a, value_b}, timeout_s=60, interval_s=3
    )
    assert final_value in (value_a, value_b), (
        f"final parameter value {final_value!r} is neither racer's value "
        f"{value_a!r}/{value_b!r} -- indicates a corrupted concurrent write"
    )

    # Stability: once resolved, the value must not flicker between independent reads. A target
    # that transiently exposes both racers' writes (a list-then-overwrite race, or a split-brain
    # merge that only self-heals later) would show as an oscillation here even though the very
    # first poll above already landed on a single value.
    for _ in range(5):
        time.sleep(2)
        again = _read_param(rds, group_name, param_name)
        assert again == final_value, (
            f"parameter value changed after settling: was {final_value!r}, now {again!r} -- "
            "the concurrent write never actually converged"
        )


def _read_param(rds, group_name, param_name):
    matches = []
    paginator = rds.get_paginator("describe_db_cluster_parameters")
    for page in paginator.paginate(DBClusterParameterGroupName=group_name):
        for p in page["Parameters"]:
            if p.get("ParameterName") == param_name:
                matches.append(p.get("ParameterValue"))
    assert len(matches) == 1, (
        f"expected exactly one {param_name!r} entry in the parameter group, found "
        f"{len(matches)}: {matches!r} -- indicates both racers' values coexisting as separate "
        "entries rather than converging to one"
    )
    return matches[0]


def _poll_for_param(rds, group_name, param_name, expected_values, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _read_param(rds, group_name, param_name)
        if last in expected_values:
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
