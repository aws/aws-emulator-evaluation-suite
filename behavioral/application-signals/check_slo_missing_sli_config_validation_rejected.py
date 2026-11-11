"""slo-missing-sli-config-validation-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "slo-missing-sli-config-validation-rejected"
GROUP = "overly-permissive"
SERVICES = ["application-signals"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateServiceLevelObjective requires exactly one of SliConfig / RequestBasedSliConfig.
    Omitting both is rejected with ValidationException, no SLO is created, and a call that supplies
    one of them still succeeds (positive control)."""
    sig = ctx.client("application-signals")
    name = ctx.unique_name("sim2real-slo-")

    code, message = _client_error(lambda: sig.create_service_level_objective(Name=name))
    assert code == "ValidationException", f"expected ValidationException for missing SLI config, got {code!r}"
    assert message == "Either SliConfig or RequestBasedSliConfig must be populated", (
        f"expected the missing-SLI-config message, got {message!r}"
    )

    all_names = {s["Name"] for s in _list_all(sig)}
    assert name not in all_names, f"SLO {name!r} must not exist after the rejected create"

    namespace = "Sim2RealBehavioral"
    metric_name = "ReqCount" + name.replace("-", "")
    control = sig.create_service_level_objective(
        Name=name,
        RequestBasedSliConfig=_request_based_sli_config(namespace, metric_name),
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )["Slo"]
    ctx.on_cleanup(lambda: _delete_slo_ignore_missing(sig, control["Arn"]))

    got = sig.get_service_level_objective(Id=control["Arn"])["Slo"]
    assert got["Name"] == name, f"expected the positive control SLO named {name!r}, got {got['Name']!r}"
    assert got["Arn"] == control["Arn"], (
        f"expected get_service_level_objective({control['Arn']!r}) to resolve, got Arn {got['Arn']!r}"
    )


def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because an
    emulator accepting input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected create_service_level_objective to be rejected, but it SUCCEEDED and returned {result!r}")


def _list_all(sig) -> list[dict]:
    out: list[dict] = []
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = sig.list_service_level_objectives(**kwargs)
        out.extend(resp.get("SloSummaries", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return out


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
