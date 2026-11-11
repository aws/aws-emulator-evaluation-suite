"""tag-resource-arn-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-arn-not-found"
GROUP = 'tagging'
SERVICES = ['route53resolver']

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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource on a nonexistent ResourceArn raises ResourceNotFoundException.

    Tagging a real FirewallDomainList succeeds, and the rejected call leaves its tags unchanged.
    """
    r53 = ctx.client("route53resolver")

    dl = r53.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
        Name=ctx.unique_name("sim2real-fdl-"),
    )["FirewallDomainList"]
    list_id = dl["Id"]
    real_arn = dl["Arn"]
    ctx.on_cleanup(lambda: r53.delete_firewall_domain_list(FirewallDomainListId=list_id))

    r53.tag_resource(ResourceArn=real_arn, Tags=[{"Key": "sim2real-control", "Value": "v"}])
    before = {t["Key"]: t["Value"] for t in r53.list_tags_for_resource(ResourceArn=real_arn)["Tags"]}
    assert before.get("sim2real-control") == "v", f"positive-control tag missing/mismatched: {before!r}"

    # Same ARN shape as the real resource, but an id that was never created.
    bogus_id = "rslvr-fdl-doesnotexist12345"
    bogus_arn = real_arn.rsplit("/", 1)[0] + "/" + bogus_id
    refusal = _error(
        lambda: r53.tag_resource(
            ResourceArn=bogus_arn, Tags=[{"Key": "k", "Value": "v"}]
        )
    )
    expected = (
        "ResourceNotFoundException",
        f'[RSLVR-02025] Can\u2019t find the resource with ID "{bogus_id}".',
    )
    assert refusal == expected, f"expected {expected!r}, got {refusal!r}"

    after = {t["Key"]: t["Value"] for t in r53.list_tags_for_resource(ResourceArn=real_arn)["Tags"]}
    assert after == before, f"real resource's tags mutated by rejected call: {after!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
