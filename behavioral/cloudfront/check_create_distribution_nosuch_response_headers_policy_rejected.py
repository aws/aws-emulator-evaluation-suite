"""create-distribution-nosuch-response-headers-policy-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-distribution-nosuch-response-headers-policy-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

#: AWS-managed response headers policy (Managed-SecurityHeadersPolicy): a real id every account
#: can attach without creating one.
_MANAGED_POLICY_ID = "67f7725c-6f97-4210-82d7-5512b31e9d03"
#: AWS-managed cache policy that disables caching.
_CACHING_DISABLED_POLICY_ID = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
_DEPLOY_DEADLINE_S = 1500.0


def _error(fn):
    """``(Error.Code, Error.Message)`` of the ClientError ``fn`` raises; a success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises, except on ``not_found``."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _wait_deployed(cf, dist_id: str, *, deadline_s: float = _DEPLOY_DEADLINE_S) -> None:
    deadline = time.monotonic() + deadline_s
    while True:
        status = cf.get_distribution(Id=dist_id)["Distribution"]["Status"]
        if status == "Deployed":
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"distribution {dist_id} still {status!r} after {deadline_s}s")
        time.sleep(3.0)


def _distribution_config(name: str, origin_id: str, response_headers_policy_id: str) -> dict:
    return {
        "CallerReference": name,
        "Comment": name,
        "Enabled": False,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": origin_id,
                    "DomainName": f"{name}.example.com",
                    "CustomOriginConfig": {
                        "HTTPPort": 80,
                        "HTTPSPort": 443,
                        "OriginProtocolPolicy": "https-only",
                    },
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": origin_id,
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": _CACHING_DISABLED_POLICY_ID,
            "ResponseHeadersPolicyId": response_headers_policy_id,
        },
    }


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDistributionWithTags refuses a cache behavior naming a response headers policy id
    that does not exist and creates no distribution; the same request naming a real policy id
    succeeds.
    """
    cf = ctx.client("cloudfront")
    origin_id = "sim2real-behav-cf-origin"

    rejected_name = ctx.unique_name("sim2real-behav-cfst-neg-")
    bogus_policy_id = str(uuid.uuid4())
    code, message = _error(
        lambda: cf.create_distribution_with_tags(
            DistributionConfigWithTags={
                "DistributionConfig": _distribution_config(rejected_name, origin_id, bogus_policy_id),
                "Tags": {"Items": [{"Key": "sim2real", "Value": rejected_name}]},
            }
        )
    )
    assert code == "NoSuchResponseHeadersPolicy", f"expected NoSuchResponseHeadersPolicy, got {code}: {message!r}"
    expected_message = "The specified response headers policy does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    found = False
    paginator = cf.get_paginator("list_distributions")
    for page in paginator.paginate():
        for item in page["DistributionList"].get("Items", []):
            if item["Comment"] == rejected_name:
                found = True
    assert not found, f"a distribution commented {rejected_name!r} exists despite the rejected create"

    control_name = ctx.unique_name("sim2real-behav-cfst-pos-")
    created = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": _distribution_config(control_name, origin_id, _MANAGED_POLICY_ID),
            "Tags": {"Items": [{"Key": "sim2real", "Value": control_name}]},
        }
    )["Distribution"]
    dist_id = created["Id"]

    def _delete_distribution() -> None:
        cfg = cf.get_distribution_config(Id=dist_id)
        body, etag = cfg["DistributionConfig"], cfg["ETag"]
        if body["Enabled"]:
            body["Enabled"] = False
            etag = cf.update_distribution(Id=dist_id, DistributionConfig=body, IfMatch=etag)["ETag"]
        _wait_deployed(cf, dist_id)
        etag = cf.get_distribution_config(Id=dist_id)["ETag"]
        cf.delete_distribution(Id=dist_id, IfMatch=etag)

    ctx.on_cleanup(_teardown(_delete_distribution, "NoSuchDistribution"))

    echoed = created["DistributionConfig"]["DefaultCacheBehavior"]["ResponseHeadersPolicyId"]
    assert echoed == _MANAGED_POLICY_ID, f"expected {_MANAGED_POLICY_ID!r} echoed back, got {echoed!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
