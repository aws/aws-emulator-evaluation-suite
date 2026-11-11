"""tag-resource-oversized-key-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-oversized-key-rejected"
GROUP = "representation"
SERVICES = ["route53resolver"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource rejects a tag Key over 128 characters with ValidationException and attaches
    nothing; a within-limit tag on the same resource then persists."""
    r53r = ctx.client("route53resolver")

    resource_arn = r53r.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-fwdl-badtag-req-"),
        Name=ctx.unique_name("sim2real-fwdl-badtag-")[:64],
    )["FirewallDomainList"]["Arn"]
    domain_list_id = resource_arn.rsplit("/", 1)[-1]
    ctx.on_cleanup(
        lambda: _safe(lambda: r53r.delete_firewall_domain_list(FirewallDomainListId=domain_list_id))
    )

    # TagKey's length limit is a model constraint, so AWS answers with the generic
    # ValidationException at request validation, not InvalidTagException.
    oversized_key = "sim2real-" + ("k" * 200)
    refusal = _error(
        lambda: r53r.tag_resource(ResourceArn=resource_arn, Tags=[{"Key": oversized_key, "Value": "x"}])
    )
    expected = (
        "ValidationException",
        f"1 validation error detected: Value '{oversized_key}' at 'tags.1.member.key' failed to "
        "satisfy constraint: Member must have length less than or equal to 128",
    )
    assert refusal == expected, f"expected {expected!r}, got {refusal!r}"

    listed = r53r.list_tags_for_resource(ResourceArn=resource_arn)["Tags"]
    assert not listed, f"oversized-key tag persisted despite rejection: {listed!r}"

    # Positive control: a within-limit tag persists.
    r53r.tag_resource(ResourceArn=resource_arn, Tags=[{"Key": "sim2real-normal-key", "Value": "ok"}])
    listed_after = r53r.list_tags_for_resource(ResourceArn=resource_arn)["Tags"]
    listed_by_key = {t["Key"]: t["Value"] for t in listed_after}
    assert listed_by_key.get("sim2real-normal-key") == "ok", (
        f"expected normal-key tag value 'ok', got {listed_by_key.get('sim2real-normal-key')!r}"
    )


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


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
