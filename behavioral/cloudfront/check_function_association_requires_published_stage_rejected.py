"""function-association-requires-published-stage-rejected."""
from __future__ import annotations

import itertools
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

_COUNTER = itertools.count()

# Managed-CachingOptimized — a stable AWS-managed cache policy id (reference data).
MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"


def _error(fn):
    """Run a call AWS refuses; return its (code, message). Raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected the call to be refused, but it succeeded with {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"timed out waiting for {description} after {timeout_s}s (last: {last!r})"
    )


def _wait_distribution_deployed(cf, dist_id, timeout_s=1800, interval_s=15, etag_hint=None):
    """Poll GetDistribution until Status == 'Deployed'; return the latest ETag.

    CloudFront is a globally scoped service and a distribution deployment
    routinely takes several minutes, so the deadline is deliberately long.
    """
    holder = {"etag": etag_hint}

    def probe():
        resp = cf.get_distribution(Id=dist_id)
        holder["etag"] = resp["ETag"]
        return resp["Distribution"]["Status"]

    _poll_until(
        probe,
        lambda status: status == "Deployed",
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"distribution {dist_id} Status=Deployed",
    )
    return holder["etag"]


def _force_delete_distribution(cf, dist_id):
    """Teardown: disable if needed, wait for Deployed, delete with the current ETag."""
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    cfg = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    etag = _wait_distribution_deployed(cf, dist_id, etag_hint=etag)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _caller_reference(ctx, prefix="cf"):
    return ctx.unique_name(f"sim2real-behav-{prefix}-") + f"-{next(_COUNTER)}"


def _custom_origin(origin_id, domain):
    return {
        "Id": origin_id,
        "DomainName": domain,
        "CustomOriginConfig": {
            "HTTPPort": 80,
            "HTTPSPort": 443,
            "OriginProtocolPolicy": "https-only",
            "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
            "OriginReadTimeout": 30,
            "OriginKeepaliveTimeout": 5,
        },
    }


def _minimal_distribution_config(
    ctx, comment="", enabled=False, origin_id="primary-origin", extra_origins=None
):
    """Minimal-but-valid DistributionConfig with a single custom origin.

    Enabled defaults to False: a disabled distribution still has to reach
    Deployed before DeleteDistribution is accepted, but teardown then skips the
    extra disable-and-redeploy round trip.
    """
    domain = f"{ctx.unique_name('sim2real-behav-origin-')}.example.com"
    origins = [_custom_origin(origin_id, domain)]
    if extra_origins:
        origins.extend(extra_origins)
    return {
        "CallerReference": _caller_reference(ctx),
        "Comment": comment,
        "Enabled": enabled,
        "Origins": {"Quantity": len(origins), "Items": origins},
        "DefaultCacheBehavior": {
            "TargetOriginId": origin_id,
            "ViewerProtocolPolicy": "redirect-to-https",
            "CachePolicyId": MANAGED_CACHING_OPTIMIZED,
        },
    }


def _create_distribution(cf, ctx, **kwargs):
    cfg = _minimal_distribution_config(ctx, **kwargs)
    resp = cf.create_distribution(DistributionConfig=cfg)
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _force_delete_distribution(cf, dist_id))
    return resp


CHECK = "function-association-requires-published-stage-rejected"
GROUP = 'functions'
SERVICES = ['cloudfront']


_FUNCTION_CODE = b"""
function handler(event) {
    var request = event.request;
    request.headers['x-sim2real-fn'] = {value: 'assoc'};
    return request;
}
"""


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Associating a DEVELOPMENT-only CloudFront Function is refused with InvalidArgument, the same
    association succeeds after PublishFunction, and an associated function fails with FunctionInUse.

    Reference: https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_PublishFunction.html
    """
    cf = ctx.client("cloudfront")
    fn_name = ctx.unique_name("sim2real-behav-fn-assoc-")
    created_fn = cf.create_function(
        Name=fn_name,
        FunctionConfig={"Comment": "sim2real association gate", "Runtime": "cloudfront-js-2.0"},
        FunctionCode=_FUNCTION_CODE,
    )

    def _delete_function():
        etag = cf.describe_function(Name=fn_name)["ETag"]
        cf.delete_function(Name=fn_name, IfMatch=etag)

    ctx.on_cleanup(_delete_function)

    meta = created_fn["FunctionSummary"]["FunctionMetadata"]
    assert meta["Stage"] == "DEVELOPMENT", f"a new function starts in DEVELOPMENT, got {meta}"
    fn_arn = meta["FunctionARN"]
    dev_etag = created_fn["ETag"]

    association = {
        "Quantity": 1,
        "Items": [{"FunctionARN": fn_arn, "EventType": "viewer-request"}],
    }

    # 1. Negative: associate the function while it is DEVELOPMENT-only. AWS answers the catch-all
    #    InvalidArgument here, not the modeled InvalidFunctionAssociation, so the message is exact.
    unpublished = _minimal_distribution_config(ctx, comment="sim2real fn-unpublished")
    unpublished["DefaultCacheBehavior"]["FunctionAssociations"] = association
    code, msg = _error(lambda: cf.create_distribution(DistributionConfig=unpublished))
    assert code == "InvalidArgument", (
        "associating a function that has never been published to LIVE must be rejected "
        "with InvalidArgument -- NOT the modeled InvalidFunctionAssociation, which "
        f"CloudFront does not use for this condition (measured on real AWS); got {code!r}: "
        f"{msg!r}"
    )
    expected_msg = (
        f"The parameter FunctionAssociationArn is invalid; {fn_name} was not found or is not published."
    )
    assert msg == expected_msg, (
        "InvalidArgument is CloudFront's catch-all, so the message is what attributes the "
        f"refusal to the function association: expected {expected_msg!r}, got {msg!r}"
    )

    # 1b. CloudFront does not distinguish "exists but unpublished" from "does not exist": a
    # FunctionARN naming a never-created function gets the same code and sentence.
    ghost_name = ctx.unique_name("sim2real-behav-fn-ghost-")
    ghost = _minimal_distribution_config(ctx, comment="sim2real fn-ghost")
    ghost["DefaultCacheBehavior"]["FunctionAssociations"] = {
        "Quantity": 1,
        "Items": [
            {
                "FunctionARN": f"{fn_arn.rsplit('/', 1)[0]}/{ghost_name}",
                "EventType": "viewer-request",
            }
        ],
    }
    ghost_code, ghost_msg = _error(
        lambda: cf.create_distribution(DistributionConfig=ghost)
    )
    assert ghost_code == code, (
        f"a FunctionARN for a function that does not exist must be refused with the same "
        f"code as an unpublished one ({code!r}), got {ghost_code!r}: {ghost_msg!r}"
    )
    assert ghost_msg == msg.replace(fn_name, ghost_name), (
        f"the two refusals must differ only in the function name -- expected "
        f"{msg.replace(fn_name, ghost_name)!r}, got {ghost_msg!r}"
    )

    # Effect absent: neither rejected CreateDistribution left a distribution behind, and
    # the function is still DEVELOPMENT-only.
    rejected_comments = {"sim2real fn-unpublished", "sim2real fn-ghost"}
    leaked = []
    for page in cf.get_paginator("list_distributions").paginate():
        for item in page["DistributionList"].get("Items", []) or []:
            if item.get("Comment") in rejected_comments:
                leaked.append((item.get("Comment"), item["Id"]))
    assert not leaked, f"a rejected CreateDistribution must not leave a distribution: {leaked}"
    assert cf.describe_function(Name=fn_name)["FunctionSummary"]["FunctionMetadata"][
        "Stage"
    ] == "DEVELOPMENT", "the rejected association must not have published the function"

    # 2. Publish, then the SAME association becomes valid -- the only thing that
    #    changed is the stage, which is exactly the invariant under test.
    published = cf.publish_function(Name=fn_name, IfMatch=dev_etag)
    assert published["FunctionSummary"]["FunctionMetadata"]["Stage"] == "LIVE", (
        published["FunctionSummary"]["FunctionMetadata"]
    )

    ok = _minimal_distribution_config(ctx, comment="sim2real fn-published")
    ok["DefaultCacheBehavior"]["FunctionAssociations"] = association
    created = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": ok,
            "Tags": {"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
        }
    )
    dist_id = created["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _force_delete_distribution(cf, dist_id))

    stored = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]
    assoc = stored["DefaultCacheBehavior"]["FunctionAssociations"]
    assert assoc["Quantity"] == 1, assoc
    assert assoc["Items"][0]["FunctionARN"] == fn_arn, assoc["Items"][0]
    assert assoc["Items"][0]["EventType"] == "viewer-request", assoc["Items"][0]

    # 3. The association is now a real reference: the function cannot be deleted.
    live_etag = cf.describe_function(Name=fn_name)["ETag"]
    code, msg = _error(lambda: cf.delete_function(Name=fn_name, IfMatch=live_etag))
    assert code == "FunctionInUse", (
        f"deleting a function associated with a distribution must fail with FunctionInUse, got {code}"
    )
    in_use_msg = f"Cannot delete function {fn_name}, it is in use by 1 distributions"
    assert msg == in_use_msg, f"expected message {in_use_msg!r}, got {msg!r}"
    assert cf.describe_function(Name=fn_name)["FunctionSummary"]["Name"] == fn_name, (
        "the function must survive the rejected delete"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
