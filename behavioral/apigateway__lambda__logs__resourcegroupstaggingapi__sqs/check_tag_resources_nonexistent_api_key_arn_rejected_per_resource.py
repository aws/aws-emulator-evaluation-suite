"""tag-resources-nonexistent-api-key-arn-rejected-per-resource."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "tag-resources-nonexistent-api-key-arn-rejected-per-resource"
GROUP = "tagging-discovery"
SERVICES = ["apigateway", "lambda", "logs", "resourcegroupstaggingapi", "sqs"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """TagResources on a real and a never-created API key ARN reports only the second in
    FailedResourcesMap (NotFoundException, 404, its exact message) and still tags the real key,
    confirmed through GetApiKey."""
    rgt = ctx.client("resourcegroupstaggingapi")
    apigw = ctx.client("apigateway")

    run_tag = ctx.unique_name("sim2real-behav-run-")
    key_name = ctx.unique_name("sim2real-behav-key-")

    created = apigw.create_api_key(name=key_name, enabled=True, tags={"Run": run_tag})
    key_id = created["id"]
    ctx.on_cleanup(lambda: apigw.delete_api_key(apiKey=key_id))

    region = ctx.region
    real_arn = f"arn:aws:apigateway:{region}::/apikeys/{key_id}"
    fake_id = "nonexistent" + uuid.uuid4().hex[:16]
    fake_arn = f"arn:aws:apigateway:{region}::/apikeys/{fake_id}"

    resp = rgt.tag_resources(ResourceARNList=[real_arn, fake_arn], Tags={"Owner": "compat"})
    failed = resp["FailedResourcesMap"]
    assert real_arn not in failed, (
        f"the REAL api key ARN was reported as failed: {failed.get(real_arn)!r} -- a batch with "
        f"one bad ARN must not sink the good one"
    )
    assert fake_arn in failed, (
        f"TagResources accepted a well-formed ARN naming an api key that was never created; "
        f"FailedResourcesMap was {failed!r}"
    )
    detail = failed[fake_arn]
    got = (detail["ErrorCode"], detail["StatusCode"], detail["ErrorMessage"])
    expected = ("NotFoundException", 404, "Invalid API Key identifier specified")
    assert got == expected, (
        f"the nonexistent api key ARN failed with (ErrorCode, StatusCode, ErrorMessage)={got!r}, "
        f"expected {expected!r}"
    )

    native = apigw.get_api_key(apiKey=key_id, includeValue=False)
    native_tags = native.get("tags") or {}
    assert native_tags.get("Owner") == "compat", (
        f"the real api key's own GetApiKey reports tags {native_tags!r}; the per-resource "
        f"failure on the OTHER arn must not have blocked this write"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
