"""list-conflicting-aliases-nonexistent-distribution-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-conflicting-aliases-nonexistent-distribution-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListConflictingAliases refuses a nonexistent DistributionId with NoSuchDistribution, and an alias
    no distribution or certificate of the caller covers with InvalidArgument and the CNAME message even
    on a real DistributionId; each with its exact message."""
    cf = ctx.client("cloudfront")
    dist_id = _create_distribution(ctx, cf)

    alias = f"{ctx.unique_name('sim2real-cf-alias-')}.example.com".lower()

    code, message = _error_code_and_message(
        lambda: cf.list_conflicting_aliases(DistributionId="EDFAKE0000001", Alias=alias)
    )
    assert code == "NoSuchDistribution", f"expected NoSuchDistribution, got {code!r}"
    assert message == "The specified distribution does not exist.", f"unexpected message {message!r}"

    code, message = _error_code_and_message(
        lambda: cf.list_conflicting_aliases(DistributionId=dist_id, Alias=alias)
    )
    assert code == "InvalidArgument", f"expected InvalidArgument for an unclaimed alias against a real distribution, got {code!r}"
    assert message == "The parameter CNAME contains one or more parameters that are not valid.", (
        f"unexpected message {message!r}"
    )


def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_distribution(ctx, cf) -> str:
    name = ctx.unique_name("sim2real-cf-conflalias-")
    created = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": {
                "CallerReference": name,
                "Comment": "sim2real behavioral check",
                "Enabled": False,
                "Origins": {
                    "Quantity": 1,
                    "Items": [
                        {
                            "Id": "origin1",
                            "DomainName": f"{name}.example.com",
                            "CustomOriginConfig": {
                                "HTTPPort": 80,
                                "HTTPSPort": 443,
                                "OriginProtocolPolicy": "match-viewer",
                            },
                        }
                    ],
                },
                "DefaultCacheBehavior": {
                    "TargetOriginId": "origin1",
                    "ViewerProtocolPolicy": "allow-all",
                    "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",
                },
            },
            "Tags": {
                "Items": [
                    {"Key": "sim2real:managed", "Value": "true"},
                    {"Key": "sim2real:prefix", "Value": "sim2real-cf-conflalias"},
                ]
            },
        }
    )
    dist_id = created["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _delete_distribution(cf, dist_id))
    return dist_id


def _delete_distribution(cf, dist_id: str, timeout_s: float = 900.0, interval_s: float = 15.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            resp = cf.get_distribution(Id=dist_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchDistribution":
                raise
            return
        if resp["Distribution"]["Status"] == "Deployed":
            cf.delete_distribution(Id=dist_id, IfMatch=resp["ETag"])
            return
        if time.monotonic() >= deadline:
            raise RuntimeError(
                f"distribution {dist_id!r} never reached Deployed within {timeout_s}s"
            )
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
