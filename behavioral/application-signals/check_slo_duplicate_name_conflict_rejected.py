"""slo-duplicate-name-conflict-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "slo-duplicate-name-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["application-signals"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a second SLO with a Name that already exists in the account is rejected with
    ConflictException, the original SLO's configuration is untouched, and creating an SLO with a
    different name still succeeds (positive control)."""
    sig = ctx.client("application-signals")
    name = ctx.unique_name("sim2real-slo-")
    namespace = "Sim2RealBehavioral"
    metric_name = "ReqCount" + name.replace("-", "")

    owner_tags = [{"Key": "sim2real-owner", "Value": "behavioral-suite"}]

    original = sig.create_service_level_objective(
        Name=name,
        Description="original",
        RequestBasedSliConfig=_request_based_sli_config(namespace, metric_name),
        Tags=owner_tags,
    )["Slo"]
    arn = original["Arn"]
    ctx.on_cleanup(lambda: _delete_slo_ignore_missing(sig, arn))

    code, message = _client_error(
        lambda: sig.create_service_level_objective(
            Name=name,
            Description="duplicate attempt",
            RequestBasedSliConfig=_request_based_sli_config(namespace, metric_name + "Dup"),
            Tags=owner_tags,
        )
    )
    assert code == "ConflictException", f"expected ConflictException on duplicate Name, got {code!r}"
    assert message == "A resource with the same identifier already exists", (
        f"expected the duplicate-name conflict message, got {message!r}"
    )

    unchanged = sig.get_service_level_objective(Id=arn)["Slo"]
    assert unchanged["Description"] == "original", (
        f"duplicate create attempt must not alter the original: expected Description='original', "
        f"got {unchanged['Description']!r}"
    )
    assert unchanged["Arn"] == arn, f"expected Arn={arn!r} unchanged, got {unchanged['Arn']!r}"

    control_name = ctx.unique_name("sim2real-slo-control-")
    control_metric = "ReqCount" + control_name.replace("-", "")
    control = sig.create_service_level_objective(
        Name=control_name,
        RequestBasedSliConfig=_request_based_sli_config(namespace, control_metric),
        Tags=owner_tags,
    )["Slo"]
    control_arn = control["Arn"]
    ctx.on_cleanup(lambda: _delete_slo_ignore_missing(sig, control_arn))

    control_seen = sig.get_service_level_objective(Id=control_arn)["Slo"]
    assert control_seen["Name"] == control_name, (
        f"control SLO with a distinct Name must succeed and be independently readable: "
        f"expected Name={control_name!r}, got {control_seen['Name']!r}"
    )


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
