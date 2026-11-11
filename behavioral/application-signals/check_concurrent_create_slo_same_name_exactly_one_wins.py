"""concurrent-create-slo-same-name-exactly-one-wins."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-slo-same-name-exactly-one-wins"
GROUP = "concurrency"
SERVICES = ["application-signals"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """N concurrent CreateServiceLevelObjective calls racing on the same Name: exactly one succeeds,
    every other racer gets ConflictException (Name uniqueness is enforced atomically)."""
    sig = ctx.client("application-signals")
    name = ctx.unique_name("sim2real-slo-race-")
    namespace = "Sim2RealBehavioral"
    metric_name = "ReqCount" + name.replace("-", "")
    racers = 8

    def attempt(_i: int):
        try:
            resp = sig.create_service_level_objective(
                Name=name,
                RequestBasedSliConfig=_request_based_sli_config(namespace, metric_name),
                Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
            )
            return ("ok", resp["Slo"]["Arn"])
        except ClientError as exc:
            return ("error", exc.response["Error"]["Code"], exc.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=racers) as pool:
        futures = [pool.submit(attempt, i) for i in range(racers)]
        results = [f.result() for f in as_completed(futures)]

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]

    assert len(successes) == 1, f"expected exactly one winner, got {len(successes)}: {results}"
    assert len(failures) == racers - 1, (
        f"expected {racers - 1} losers, got {len(failures)}: {results}"
    )
    assert all(code == "ConflictException" for _, code, _m in failures), (
        f"expected every loser to fail with ConflictException, got codes: "
        f"{[code for _, code, _m in failures]}"
    )
    expected = "A resource with the same identifier already exists"
    assert all(message == expected for _, _c, message in failures), (
        f"expected every loser's message to be {expected!r}, got: "
        f"{[message for _, _c, message in failures]}"
    )

    winner_arn = successes[0][1]
    ctx.on_cleanup(lambda: _delete_slo_ignore_missing(sig, winner_arn))

    got = sig.get_service_level_objective(Id=winner_arn)["Slo"]
    assert got["Name"] == name, f"expected winner's Name to be {name!r}, got {got['Name']!r}"


def _delete_slo_ignore_missing(sig, arn: str) -> None:
    try:
        sig.delete_service_level_objective(Id=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _request_based_sli_config(namespace: str, metric_name: str) -> dict:
    return {
        "RequestBasedSliMetricConfig": {
            "TotalRequestCountMetric": [
                {
                    "Id": "total",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": namespace,
                            "MetricName": metric_name,
                            "Dimensions": [],
                        },
                        "Period": 300,
                        "Stat": "Sum",
                    },
                    "ReturnData": True,
                }
            ],
            "MonitoredRequestCountMetric": {
                "BadCountMetric": [
                    {
                        "Id": "bad",
                        "MetricStat": {
                            "Metric": {
                                "Namespace": namespace,
                                "MetricName": f"{metric_name}Errors",
                                "Dimensions": [],
                            },
                            "Period": 300,
                            "Stat": "Sum",
                        },
                        "ReturnData": True,
                    }
                ]
            },
        }
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
