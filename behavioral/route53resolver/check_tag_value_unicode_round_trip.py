"""tag-value-unicode-round-trip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-value-unicode-round-trip"
GROUP = "server-side"
SERVICES = ["route53resolver"]


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
    """A tag value of accented Latin, CJK and Greek letters on a FirewallDomainList round-trips
    unchanged through ListTagsForResource, and after the list is deleted GetFirewallDomainList and
    TagResource on it are both refused as not found.
    """
    r53 = ctx.client("route53resolver")

    resp = r53.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("cr-"),
        Name=ctx.unique_name("sim2real-fdl-"),
    )
    fdl = resp["FirewallDomainList"]
    arn = fdl["Arn"]
    list_id = fdl["Id"]
    ctx.on_cleanup(lambda: _absent(lambda: r53.delete_firewall_domain_list(FirewallDomainListId=list_id)))

    unicode_value = "héllo-wörld-日本語-Ωμέγα"
    tag_key = "sim2real-unicode-tag"

    r53.tag_resource(ResourceArn=arn, Tags=[{"Key": tag_key, "Value": unicode_value}])

    listed = r53.list_tags_for_resource(ResourceArn=arn)["Tags"]
    matching = [t for t in listed if t["Key"] == tag_key]
    assert len(matching) == 1, f"expected exactly one tag with key {tag_key!r}, got {listed!r}"
    assert matching[0]["Value"] == unicode_value, (
        f"tag value mutated in round trip: sent {unicode_value!r}, got {matching[0]['Value']!r}"
    )

    r53.delete_firewall_domain_list(FirewallDomainListId=list_id)

    # Deletion is asynchronous: Get keeps succeeding (Status DELETING) for a window
    # before the id genuinely disappears, so absence is a bounded poll, not one read.
    deadline = time.monotonic() + 60.0
    while not _absent(lambda: r53.get_firewall_domain_list(FirewallDomainListId=list_id)):
        if time.monotonic() >= deadline:
            raise AssertionError("a deleted FirewallDomainList still reads back after 60s")
        time.sleep(2.0)
    expected = (
        "ResourceNotFoundException",
        f'[RSLVR-02025] Can\u2019t find the resource with ID "{list_id}".',
    )
    gone = _error(lambda: r53.get_firewall_domain_list(FirewallDomainListId=list_id))
    assert gone == expected, (
        f"expected a deleted FirewallDomainList to read back {expected!r}, got {gone!r}"
    )

    retag = _error(
        lambda: r53.tag_resource(ResourceArn=arn, Tags=[{"Key": tag_key, "Value": unicode_value}])
    )
    assert retag == expected, (
        f"expected TagResource on a deleted FirewallDomainList's ARN to fail with "
        f"{expected!r}, got {retag!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
