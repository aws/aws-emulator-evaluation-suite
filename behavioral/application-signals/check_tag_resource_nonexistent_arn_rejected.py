"""tag-resource-nonexistent-arn-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-nonexistent-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["application-signals"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource against an ARN that does not correspond to any existing SLO is rejected with
    ResourceNotFoundException, no tags are stored anywhere as a side effect, and tagging a real SLO
    ARN still succeeds (positive control)."""
    sig = ctx.client("application-signals")
    name = ctx.unique_name("sim2real-slo-")
    namespace = "Sim2RealBehavioral"
    metric_name = "ReqCount" + name.replace("-", "")

    created = sig.create_service_level_objective(
        Name=name,
        RequestBasedSliConfig=_request_based_sli_config(namespace, metric_name),
    )["Slo"]
    real_arn = created["Arn"]
    ctx.on_cleanup(lambda: _delete_slo_ignore_missing(sig, real_arn))

    bogus_arn = real_arn.rsplit("/", 1)[0] + "/sim2real-does-not-exist-" + name

    code, message = _client_error(
        lambda: sig.tag_resource(
            ResourceArn=bogus_arn, Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}]
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == f"Resource with arn '{bogus_arn}' does not exist.", (
        f"expected the not-found message for {bogus_arn!r}, got {message!r}"
    )

    real_tags = sig.list_tags_for_resource(ResourceArn=real_arn)["Tags"]
    assert real_tags == [], f"expected no tags on {real_arn} after the rejected call, got {real_tags!r}"

    sig.tag_resource(ResourceArn=real_arn, Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}])
    control_tags = sig.list_tags_for_resource(ResourceArn=real_arn)["Tags"]
    expected_tag = {"Key": "sim2real-owner", "Value": "behavioral-suite"}
    assert expected_tag in control_tags, f"expected {expected_tag!r} in {control_tags!r}"


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
