"""update-vpc-link-invalid-patch-op-rejected."""
from __future__ import annotations

import uuid
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-vpc-link-invalid-patch-op-rejected"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']


def _client_error(fn):
    """Call fn(); return its botocore Error dict (Code and Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")

def _fake_nlb_arn(ctx):
    """A syntactically-valid NLB ARN that references no real NLB (CreateVpcLink only
    format-checks the ARN synchronously)."""
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    suffix = uuid.uuid4().hex[:16]
    return (
        f"arn:aws:elasticloadbalancing:{ctx.region}:{account_id}:"
        f"loadbalancer/net/sim2real-behav-nlb/{suffix}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateVpcLink with a non-JSON-Patch `op` must be rejected with ValidationException.

    An `op` that is not one of add/remove/replace/copy/move/test must not be silently ignored
    or half-applied (overly-permissive check).
    """
    ag = ctx.client("apigateway")
    target_arn = _fake_nlb_arn(ctx)
    created = ag.create_vpc_link(
        name=ctx.unique_name("sim2real-behav-vpclink-"),
        targetArns=[target_arn],
        tags={"sim2real": "update-vpc-link-invalid-patch-op-rejected"},
    )
    vpc_link_id = created["id"]
    ctx.on_cleanup(lambda: ag.delete_vpc_link(vpcLinkId=vpc_link_id))

    err = _client_error(
        lambda: ag.update_vpc_link(
            vpcLinkId=vpc_link_id,
            patchOperations=[{"op": "not-a-real-op", "path": "/description", "value": "x"}],
        )
    )
    expected = (
        "1 validation error detected: Value 'not-a-real-op' at "
        "'updateVpcLinkInput.patchOperations.1.member.op' failed to satisfy constraint: "
        "Member must satisfy enum value set: [add, remove, move, test, replace, copy]"
    )
    assert (err.get("Code"), err.get("Message")) == ("ValidationException", expected), (
        f"expected ValidationException for an invalid JSON-Patch op, got {err!r}"
    )

    unchanged = ag.get_vpc_link(vpcLinkId=vpc_link_id)
    assert not unchanged.get("description"), (
        f"a rejected patch must not have applied any description, got {unchanged.get('description')!r}"
    )

    # Positive control: the same wiring accepts a valid JSON-Patch op, proving the
    # rejection above is specific to the bad `op` rather than update_vpc_link being
    # broken for every patch (or the harness never reaching the target at all).
    ag.update_vpc_link(
        vpcLinkId=vpc_link_id,
        patchOperations=[{"op": "replace", "path": "/description", "value": "sim2real-behav-desc"}],
    )
    applied = ag.get_vpc_link(vpcLinkId=vpc_link_id)
    assert applied.get("description") == "sim2real-behav-desc", (
        f"expected the valid patch to apply, got description={applied.get('description')!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
