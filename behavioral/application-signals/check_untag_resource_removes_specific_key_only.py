"""untag-resource-removes-specific-key-only."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-resource-removes-specific-key-only"
GROUP = "data-plane"
SERVICES = ["application-signals"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource with one TagKey removes only that tag and leaves the other tags on the
    resource untouched."""
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

    sig.tag_resource(
        ResourceArn=arn,
        Tags=[
            {"Key": "sim2real-team", "Value": "checkout"},
            {"Key": "sim2real-env", "Value": "test"},
        ],
    )

    sig.untag_resource(ResourceArn=arn, TagKeys=["sim2real-team"])

    remaining = sig.list_tags_for_resource(ResourceArn=arn)["Tags"]
    remaining_keys = {t["Key"] for t in remaining}
    assert remaining_keys == {"sim2real-env"}, (
        f"expected only 'sim2real-env' to survive UntagResource(TagKeys=['sim2real-team']), "
        f"got keys {remaining_keys}"
    )
    assert {"Key": "sim2real-env", "Value": "test"} in remaining, (
        f"expected the untouched tag to keep its original value "
        f"{{'Key': 'sim2real-env', 'Value': 'test'}}, got {remaining}"
    )


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
