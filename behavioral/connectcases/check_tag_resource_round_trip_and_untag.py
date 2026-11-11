"""tag-resource-round-trip-and-untag."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-round-trip-and-untag"
GROUP = "data-plane"
SERVICES = ["connectcases"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource attaches tags visible via ListTagsForResource, and UntagResource
    removes exactly the requested key while the request completes."""
    cc = ctx.client("connectcases")
    domain_id = _create_active_domain(ctx)
    domain_arn = cc.get_domain(domainId=domain_id)["domainArn"]

    cc.tag_resource(arn=domain_arn, tags={"Environment": "sim2real-test", "Owner": "behavioral"})

    tags_after_put = cc.list_tags_for_resource(arn=domain_arn)["tags"]
    assert tags_after_put.get("Environment") == "sim2real-test", (
        f"expected Environment=sim2real-test after TagResource, got {tags_after_put}"
    )
    assert tags_after_put.get("Owner") == "behavioral", (
        f"expected Owner=behavioral after TagResource, got {tags_after_put}"
    )

    cc.untag_resource(arn=domain_arn, tagKeys=["Environment"])

    tags_after_untag = cc.list_tags_for_resource(arn=domain_arn)["tags"]
    assert "Environment" not in tags_after_untag, f"Environment tag should be gone, got {tags_after_untag}"
    assert tags_after_untag.get("Owner") == "behavioral", (
        f"expected Owner=behavioral to survive UntagResource(Environment), got {tags_after_untag}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _delete_domain(ctx, domain_id):
    cc = ctx.client("connectcases")
    for _ in range(5):
        try:
            cc.delete_domain(domainId=domain_id)
            return
        except ClientError as err:
            if err.response["Error"]["Code"] != "ConflictException":
                raise
            time.sleep(3.0)
    cc.delete_domain(domainId=domain_id)


def _create_active_domain(ctx):
    cc = ctx.client("connectcases")
    name = ctx.unique_name("sim2real-cc-domain-")
    domain_id = cc.create_domain(name=name)["domainId"]
    ctx.on_cleanup(lambda: _delete_domain(ctx, domain_id))
    status = _poll_until(
        lambda: cc.get_domain(domainId=domain_id)["domainStatus"],
        lambda s: s != "CreationInProgress",
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert status == "Active", f"domain reached terminal status {status!r}, expected Active"
    return domain_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
