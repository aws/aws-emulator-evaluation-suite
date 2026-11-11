"""api-key-discovered-tagged-and-removed-from-index-on-delete."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "api-key-discovered-tagged-and-removed-from-index-on-delete"
GROUP = "tagging-discovery"
SERVICES = ["apigateway", "lambda", "logs", "resourcegroupstaggingapi", "sqs"]


@tags("axis:happy-path", "cap:c2", "plane:control")
def run(ctx) -> None:
    """An API key tagged at creation is found by GetResources under an ARN ending ::/apikeys/<id>,
    TagResources/UntagResources on that ARN reach GetApiKey's native tags, and
    deleting the key retracts it from the tagging index with no explicit untag."""
    rgt = ctx.client("resourcegroupstaggingapi")
    apigw = ctx.client("apigateway")

    run_tag = ctx.unique_name("sim2real-behav-run-")
    key_name = ctx.unique_name("sim2real-behav-key-")

    created = apigw.create_api_key(
        name=key_name, enabled=True, tags={"Run": run_tag, "Stage": "initial"},
    )
    key_id = created["id"]
    deleted = {"value": False}

    def _cleanup_key():
        if not deleted["value"]:
            apigw.delete_api_key(apiKey=key_id)

    ctx.on_cleanup(_cleanup_key)

    matched = _poll_until(
        lambda: rgt.get_resources(
            ResourceTypeFilters=["apigateway:apikeys"],
            TagFilters=[{"Key": "Run", "Values": [run_tag]}],
        )["ResourceTagMappingList"],
        lambda mappings: len(mappings) == 1,
        timeout_s=120.0,
    )
    assert len(matched) == 1, f"GetResources matched {len(matched)} resources, expected exactly 1"
    arn = matched[0]["ResourceARN"]
    assert arn.endswith("::/apikeys/" + key_id), (
        f"discovered ARN {arn!r} does not have the apikeys ARN shape ending '::/apikeys/{key_id}'"
    )
    tags_now = {t["Key"]: t["Value"] for t in matched[0]["Tags"]}
    assert tags_now == {"Run": run_tag, "Stage": "initial"}, (
        f"tagging-api index reports {tags_now!r}, expected exactly Run and Stage"
    )

    rgt.tag_resources(ResourceARNList=[arn], Tags={"Owner": "compat"})
    rgt.untag_resources(ResourceARNList=[arn], TagKeys=["Stage"])

    settled = _poll_until(
        lambda: rgt.get_resources(
            ResourceTypeFilters=["apigateway:apikeys"],
            TagFilters=[{"Key": "Run", "Values": [run_tag]}, {"Key": "Owner", "Values": ["compat"]}],
        )["ResourceTagMappingList"],
        lambda mappings: len(mappings) == 1,
        timeout_s=120.0,
    )
    assert len(settled) == 1, (
        f"after TagResources(Owner=compat), re-query matched {len(settled)}, expected exactly 1"
    )
    settled_tags = {t["Key"]: t["Value"] for t in settled[0]["Tags"]}
    assert "Stage" not in settled_tags, (
        f"UntagResources(Stage) left Stage in the index: {settled_tags!r}"
    )

    native = apigw.get_api_key(apiKey=key_id, includeValue=False)
    native_tags = native.get("tags") or {}
    assert native_tags == {"Run": run_tag, "Owner": "compat"}, (
        f"API Gateway's own GetApiKey reports tags {native_tags!r} after writes made through "
        f"the tagging API; expected exactly Run and Owner"
    )

    apigw.delete_api_key(apiKey=key_id)
    deleted["value"] = True

    gone = _poll_until(
        lambda: rgt.get_resources(
            ResourceTypeFilters=["apigateway:apikeys"],
            TagFilters=[{"Key": "Run", "Values": [run_tag]}],
        )["ResourceTagMappingList"],
        lambda mappings: mappings == [],
        timeout_s=120.0,
    )
    assert gone == [], (
        f"deleting the api key did not retract it from the tagging index: {gone!r} still matched"
    )


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while time.monotonic() < deadline:
        if predicate(last):
            return last
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
