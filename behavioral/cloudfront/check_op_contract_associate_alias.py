"""op-contract-associate-alias."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

CHECK = "op-contract-associate-alias"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


from behavioral_harness import tags


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateAlias refuses a nonexistent target distribution with NoSuchDistribution and an alias no
    certificate on the caller's distributions covers with InvalidArgument, each with its exact
    message, and leaves the target's alias list without the alias."""
    cf = ctx.client("cloudfront")
    dist_id, etag = _create_minimal_distribution(ctx)
    alias = f"{ctx.unique_name('sim2real-behav-alias-')}.example.com".lower()

    # Boundary 1: target distribution does not exist.
    code, message = _error(lambda: cf.associate_alias(TargetDistributionId="EDFDVBD6EXAMPLE", Alias=alias))
    assert code == "NoSuchDistribution", f"expected NoSuchDistribution, got {code}"
    expected = "The specified distribution does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Boundary 2: alias is not currently associated with any distribution / no cert covers it.
    code, message = _error(lambda: cf.associate_alias(TargetDistributionId=dist_id, Alias=alias))
    assert code == "InvalidArgument", f"expected InvalidArgument, got {code}"
    expected = "The parameter Alias contains one or more parameters that are not valid."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # No side effect: the target distribution's alias list must remain untouched.
    cfg = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]
    aliases = cfg.get("Aliases", {}).get("Items", [])
    assert alias not in aliases, "AssociateAlias must not mutate state on failure"


def _error(fn):
    """Call fn(); return (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises: an emulator accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_minimal_distribution(ctx):
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-behav-dist-")
    config = {
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
            "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",  # CachingOptimized
        },
    }
    resp = cf.create_distribution(DistributionConfig=config)
    dist_id = resp["Distribution"]["Id"]
    etag = resp["ETag"]
    ctx.on_cleanup(lambda: _delete_distribution_best_effort(ctx, dist_id))
    return dist_id, etag


def _delete_distribution_best_effort(ctx, dist_id):
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + 900.0
    try:
        while time.monotonic() < deadline:
            resp = cf.get_distribution(Id=dist_id)
            if resp["Distribution"]["Status"] == "Deployed":
                cf.delete_distribution(Id=dist_id, IfMatch=resp["ETag"])
                return
            time.sleep(15)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchDistribution":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
