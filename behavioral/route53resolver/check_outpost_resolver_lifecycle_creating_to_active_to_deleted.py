"""outpost-resolver-lifecycle-creating-to-active-to-deleted."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "outpost-resolver-lifecycle-creating-to-active-to-deleted"
GROUP = "state-machine"
SERVICES = ["route53resolver"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateOutpostResolver for a nonexistent Outpost ARN fails with ValidationException naming the
    ARN and lists no resolver; the full lifecycle needs a racked Outposts device no API provisions.
    ListOutpostResolvers answering normally shows the rejection is specific to the missing Outpost."""
    r53r = ctx.client("route53resolver")
    control = r53r.list_outpost_resolvers()
    assert "OutpostResolvers" in control, "positive control failed: ListOutpostResolvers did not answer normally"

    name = ctx.unique_name("sim2real-outres-lc-")[:255]
    fake_outpost_arn = (
        f"arn:aws:outposts:{ctx.region}:"
        f"{ctx.client('sts').get_caller_identity()['Account']}:outpost/op-00000000deadbeef0"
    )
    try:
        r53r.create_outpost_resolver(
            CreatorRequestId=ctx.unique_name("sim2real-outres-lc-req-"),
            Name=name,
            PreferredInstanceType="m5.large",
            OutpostArn=fake_outpost_arn,
            InstanceCount=4,
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message", "")
    else:
        raise AssertionError(
            "CreateOutpostResolver against a nonexistent Outpost ARN unexpectedly "
            "succeeded -- a real OutpostResolver is now on file that this check has no "
            "resolver id to clean up"
        )

    assert code == "ValidationException", f"expected ValidationException for a nonexistent Outpost, got {code!r}"
    expected = f'[RSLVR-03007] Cannot find the Outpost with Arn "{fake_outpost_arn}".'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    listed = r53r.list_outpost_resolvers()["OutpostResolvers"]
    assert not any(r["Name"] == name for r in listed), (
        f"rejected CreateOutpostResolver still produced a listed resolver named {name!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
