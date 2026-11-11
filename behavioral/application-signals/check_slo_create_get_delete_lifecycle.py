"""slo-create-get-delete-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "slo-create-get-delete-lifecycle"
GROUP = "lifecycle"
SERVICES = ["application-signals"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A created SLO is retrievable with matching fields, then fully disappears after delete."""
    sig = ctx.client("application-signals")
    name = ctx.unique_name("sim2real-slo-")
    namespace = "Sim2RealBehavioral"
    metric_name = "ReqCount" + name.replace("-", "")

    created = sig.create_service_level_objective(
        Name=name,
        Description="lifecycle test slo",
        RequestBasedSliConfig=_request_based_sli_config(namespace, metric_name),
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )["Slo"]
    arn = created["Arn"]
    ctx.on_cleanup(lambda: _delete_slo_ignore_missing(sig, arn))

    assert created["Name"] == name, f"expected Name {name!r}, got {created['Name']!r}"
    assert created["EvaluationType"] == "RequestBased", (
        f"expected EvaluationType 'RequestBased', got {created['EvaluationType']!r}"
    )

    got = sig.get_service_level_objective(Id=arn)["Slo"]
    assert got["Name"] == name, f"expected Name {name!r} on GetServiceLevelObjective, got {got['Name']!r}"
    assert got["Arn"] == arn, f"expected Arn {arn!r} on GetServiceLevelObjective, got {got['Arn']!r}"
    assert got["Description"] == "lifecycle test slo", (
        f"expected Description 'lifecycle test slo', got {got['Description']!r}"
    )

    names_before = {s["Name"] for s in _list_all_slo_names(sig)}
    assert name in names_before, f"expected {name!r} in ListServiceLevelObjectives, got {names_before!r}"

    sig.delete_service_level_objective(Id=arn)

    code, message = _client_error(lambda: sig.get_service_level_objective(Id=arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException on Get after delete, got {code!r}"
    )
    assert message == f"Slo with arn '{arn}' does not exist.", (
        f"expected the not-found message for {arn!r} on Get after delete, got {message!r}"
    )

    # message varies: AWS names an internal per-account work-item id the check cannot know
    mutate_code, _ = _client_error(
        lambda: sig.update_service_level_objective(Id=arn, Description="post-delete-update")
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"expected a mutation on a deleted SLO to be rejected as not-found, got {mutate_code!r}"
    )

    names_after = {s["Name"] for s in _list_all_slo_names(sig)}
    assert name not in names_after, f"expected {name!r} absent from ListServiceLevelObjectives, got {names_after!r}"


def _client_error(fn) -> tuple[str, str]:
    """Call fn() and return the (code, message) it is rejected with; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


def _delete_slo_ignore_missing(sig, arn: str) -> None:
    try:
        sig.delete_service_level_objective(Id=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _list_all_slo_names(sig) -> list[dict]:
    out = []
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = sig.list_service_level_objectives(**kwargs)
        out.extend(resp.get("SloSummaries", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return out


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
