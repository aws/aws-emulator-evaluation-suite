"""concurrent-create-deployment-invalid-workload-all-rejected."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-create-deployment-invalid-workload-all-rejected"
GROUP = "concurrency"
SERVICES = ["launch-wizard"]


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateDeployment calls for the same nonexistent workload each get ResourceNotFoundException,
    and none of them leaves a deployment record behind."""
    lw = ctx.client("launch-wizard")
    bogus_workload = "Sim2RealNoSuchWorkloadXyz"
    n_racers = 6
    names = [ctx.unique_name(f"sim2real-lw-race-{i}-") for i in range(n_racers)]

    def _racer(name: str) -> tuple[str, str | None] | None:
        return _error_code(
            lambda: lw.create_deployment(
                workloadName=bogus_workload,
                deploymentPatternName="bogusPattern1",
                name=name,
                specifications={"Placeholder": "value"},
            )
        )

    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        codes = list(pool.map(_racer, names))

    expected = (
        "ResourceNotFoundException",
        "The specified workload does not exist or insufficient permissions.",
    )
    for i, code in enumerate(codes):
        assert code == expected, (
            f"racer {i} expected {expected!r}, got {code!r}"
        )

    listed = lw.list_deployments(maxResults=100)["deployments"]
    listed_names = {d["name"] for d in listed}
    leaked = listed_names.intersection(names)
    assert not leaked, f"concurrent invalid creates leaked deployment records: {leaked}"

    # positive control: the API channel and a real lookup still work, so the
    # rejections above are specific to the nonexistent workload, not a broken channel
    lw.list_workloads(maxResults=1)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
