"""tag-resource-list-untag-roundtrip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-list-untag-roundtrip"
GROUP = "data-plane"
SERVICES = ["application-signals"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags applied to an SLO via TagResource are visible via ListTagsForResource and gone after
    UntagResource."""
    sig = ctx.client("application-signals")
    name = ctx.unique_name("sim2real-slo-")
    namespace = "Sim2RealBehavioral"
    metric_name = "ReqCount" + name.replace("-", "")

    created = sig.create_service_level_objective(
        Name=name,
        RequestBasedSliConfig=_request_based_sli_config(namespace, metric_name),
    )["Slo"]
    arn = created["Arn"]
    ctx.on_cleanup(lambda: _delete_slo_ignore_missing(sig, arn))

    before = sig.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert before == [], f"expected no tags on a freshly created SLO, got {before}"

    sig.tag_resource(ResourceArn=arn, Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}])

    after_tag = sig.list_tags_for_resource(ResourceArn=arn)["Tags"]
    expected_tag = {"Key": "sim2real-owner", "Value": "behavioral-suite"}
    assert expected_tag in after_tag, f"expected {expected_tag} in tags after TagResource, got {after_tag}"

    sig.untag_resource(ResourceArn=arn, TagKeys=["sim2real-owner"])

    after_untag = sig.list_tags_for_resource(ResourceArn=arn)["Tags"]
    assert after_untag == [], f"expected no tags after UntagResource, got {after_untag}"


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
