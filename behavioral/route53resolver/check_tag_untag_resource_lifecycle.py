"""tag-untag-resource-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-untag-resource-lifecycle"
GROUP = 'tagging'
SERVICES = ['route53resolver']

def _poll(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


_TRACE_ID = ' Trace Id: "'


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises, with the
    per-request X-Ray trace id suffix removed. A call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        message = err.get("Message", "")
        head, sep, _ = message.rpartition(_TRACE_ID)
        return err.get("Code"), (head if sep and message.endswith('"') else message)
    raise AssertionError(f"expected a ClientError, the call succeeded and returned {result!r}")


def _absent(fn) -> bool:
    """True once fn() raises ResourceNotFoundException, False while it still succeeds."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return True
        raise
    return False



@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource adds tags visible via ListTagsForResource; UntagResource removes them; once the
    resource itself is deleted, the same read and a further mutation are both refused."""
    r53 = ctx.client("route53resolver")
    dl = r53.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"), Name=ctx.unique_name("sim2real-behav-fdl-")
    )["FirewallDomainList"]
    list_id = dl["Id"]
    arn = dl["Arn"]
    ctx.on_cleanup(lambda: _absent(lambda: r53.delete_firewall_domain_list(FirewallDomainListId=list_id)))

    r53.tag_resource(
        ResourceArn=arn, Tags=[{"Key": "env", "Value": "behavioral-test"}]
    )

    def read_tags():
        return {t["Key"]: t["Value"] for t in r53.list_tags_for_resource(ResourceArn=arn)["Tags"]}

    _poll(
        read_tags, lambda t: t.get("env") == "behavioral-test", timeout_s=30, interval_s=1,
        description="ListTagsForResource reflecting env=behavioral-test after TagResource",
    )

    r53.untag_resource(ResourceArn=arn, TagKeys=["env"])
    _poll(
        read_tags, lambda t: "env" not in t, timeout_s=30, interval_s=1,
        description="ListTagsForResource no longer reporting key 'env' after UntagResource",
    )

    r53.delete_firewall_domain_list(FirewallDomainListId=list_id)
    # DeleteFirewallDomainList is async: GetFirewallDomainList keeps returning Status=DELETING
    # (a 200) for a while, so the not-found read is a bounded wait, never an immediate assertion.
    _poll(
        lambda: _absent(lambda: r53.get_firewall_domain_list(FirewallDomainListId=list_id)),
        lambda gone: gone,
        timeout_s=90, interval_s=3,
        description="GetFirewallDomainList reporting ResourceNotFoundException after delete",
    )

    mutate = _error(
        lambda: r53.tag_resource(ResourceArn=arn, Tags=[{"Key": "env", "Value": "behavioral-test"}])
    )
    expected = (
        "ResourceNotFoundException",
        f'[RSLVR-02025] Can\u2019t find the resource with ID "{list_id}".',
    )
    assert mutate == expected, f"expected TagResource on a deleted resource to raise {expected!r}, got {mutate!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
