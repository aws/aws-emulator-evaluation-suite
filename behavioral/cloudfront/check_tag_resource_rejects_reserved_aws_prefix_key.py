"""tag-resource-rejects-reserved-aws-prefix-key."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-resource-rejects-reserved-aws-prefix-key"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

_MANAGED_CACHING_OPTIMIZED_CACHE_POLICY_ID = "658327ea-f89d-4fab-a63d-7e88639e58f6"


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, it succeeded with {result!r}")


def _minimal_distribution_config(caller_ref):
    return {
        "CallerReference": caller_ref,
        "Comment": caller_ref,
        "Enabled": False,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "primary-origin",
                    "DomainName": "example.com",
                    "CustomOriginConfig": {
                        "HTTPPort": 80,
                        "HTTPSPort": 443,
                        "OriginProtocolPolicy": "https-only",
                        "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
                    },
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "primary-origin",
            "ViewerProtocolPolicy": "redirect-to-https",
            "CachePolicyId": _MANAGED_CACHING_OPTIMIZED_CACHE_POLICY_ID,
        },
    }


def _teardown_delete_distribution(cf, dist_id):
    def run_undo() -> None:
        try:
            resp = cf.get_distribution(Id=dist_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchDistribution":
                return
            raise
        deadline = time.monotonic() + 850.0
        status = resp["Distribution"]["Status"]
        while status != "Deployed" and time.monotonic() < deadline:
            time.sleep(15)
            resp = cf.get_distribution(Id=dist_id)
            status = resp["Distribution"]["Status"]
        if status != "Deployed":
            raise AssertionError(f"distribution {dist_id} never reached Deployed for teardown, last={status!r}")
        cf.delete_distribution(Id=dist_id, IfMatch=resp["ETag"])

    return run_undo


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource on an existing distribution with a tag key starting "aws:" is refused
    with InvalidTagging and its exact message, and ListTagsForResource afterward shows the
    distribution's tags unchanged: the reserved key never attaches.
    """
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-behav-distaws-")

    resp = cf.create_distribution(DistributionConfig=_minimal_distribution_config(caller_ref))
    dist = resp["Distribution"]
    dist_id = dist["Id"]
    dist_arn = dist["ARN"]
    ctx.on_cleanup(_teardown_delete_distribution(cf, dist_id))

    pre = cf.list_tags_for_resource(Resource=dist_arn)["Tags"]["Items"]
    assert pre == [], f"expected no tags on a freshly created distribution, got {pre!r}"

    # Positive control: an ordinary tag key attaches via TagResource.
    control_key, control_value = "sim2real-owner", "behavioral-check"
    cf.tag_resource(Resource=dist_arn, Tags={"Items": [{"Key": control_key, "Value": control_value}]})
    after_control = cf.list_tags_for_resource(Resource=dist_arn)["Tags"]["Items"]
    control_map = {t["Key"]: t["Value"] for t in after_control}
    assert control_map == {control_key: control_value}, (
        f"expected only the control tag {control_key}={control_value!r} after TagResource, got {control_map!r}"
    )

    # The refusal under test: a reserved "aws:" key prefix on TagResource.
    code, message = _error(
        lambda: cf.tag_resource(Resource=dist_arn, Tags={"Items": [{"Key": "aws:owner", "Value": "behavioral-check"}]})
    )
    assert code == "InvalidTagging", f"expected InvalidTagging, got {code!r}: {message!r}"
    expected_message = "Tag key cannot start with 'aws:'."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Proof the refusal had no effect: tags are exactly what the control left behind.
    after_refusal = cf.list_tags_for_resource(Resource=dist_arn)["Tags"]["Items"]
    refusal_map = {t["Key"]: t["Value"] for t in after_refusal}
    assert refusal_map == {control_key: control_value}, (
        f"expected tags unchanged by the refused call, got {refusal_map!r}"
    )
    assert not any(k.startswith("aws:") for k in refusal_map), (
        f"an 'aws:'-prefixed key leaked into the distribution's tags: {refusal_map!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
