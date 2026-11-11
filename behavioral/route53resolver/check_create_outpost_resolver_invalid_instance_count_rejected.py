"""create-outpost-resolver-invalid-instance-count-rejected."""
from __future__ import annotations

import random

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-outpost-resolver-invalid-instance-count-rejected"
GROUP = "overly-permissive"
SERVICES = ["route53resolver"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateOutpostResolver with InstanceCount below 4 is rejected with an instance-count message,
    not clamped; with a valid count the same nonexistent OutpostArn fails on the Outpost instead.
    """
    r53r = ctx.client("route53resolver")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    op_suffix = "".join(random.choices("0123456789abcdef", k=17))
    bogus_outpost_arn = f"arn:aws:outposts:{ctx.region}:{account_id}:outpost/op-{op_suffix}"

    name_invalid = ctx.unique_name("sim2real-behav-outpost-invalid-")
    code_invalid, msg_invalid = _error_code_and_message(
        lambda: r53r.create_outpost_resolver(
            CreatorRequestId=ctx.unique_name("sim2real-behav-creq-"),
            Name=name_invalid,
            PreferredInstanceType="r5.large",
            OutpostArn=bogus_outpost_arn,
            InstanceCount=1,
        )
    )
    assert code_invalid == "ValidationException", f"expected ValidationException, got {code_invalid}"
    assert msg_invalid == '[RSLVR-03002] The instance count must be equal to or greater than "4".', (
        f"expected the out-of-range InstanceCount to be called out in the error message, got {msg_invalid!r}"
    )

    # Effect absent: no resolver was left behind under that name.
    names_after_invalid = {r["Name"] for r in r53r.list_outpost_resolvers().get("OutpostResolvers", [])}
    assert name_invalid not in names_after_invalid, "an OutpostResolver leaked from a rejected create call"

    # A missing Outpost is also a ValidationException, so only the message shows that the
    # instance-count check above ran rather than a blanket refusal.
    name_valid_count = ctx.unique_name("sim2real-behav-outpost-validcount-")
    code_valid_count, msg_valid_count = _error_code_and_message(
        lambda: r53r.create_outpost_resolver(
            CreatorRequestId=ctx.unique_name("sim2real-behav-creq-"),
            Name=name_valid_count,
            PreferredInstanceType="r5.large",
            OutpostArn=bogus_outpost_arn,
            InstanceCount=4,
        )
    )
    assert code_valid_count == "ValidationException", f"expected ValidationException, got {code_valid_count}"
    assert msg_valid_count == f'[RSLVR-03007] Cannot find the Outpost with Arn "{bogus_outpost_arn}".', (
        f"expected the valid-count call to fail on the Outpost lookup instead, got {msg_valid_count!r}"
    )

    names_after_valid = {r["Name"] for r in r53r.list_outpost_resolvers().get("OutpostResolvers", [])}
    assert name_valid_count not in names_after_valid, "an OutpostResolver leaked from a rejected create call"


def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

