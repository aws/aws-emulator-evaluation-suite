"""get-vpc-link-nonexistent-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-vpc-link-nonexistent-not-found"
GROUP = 'overly-permissive'
SERVICES = ['apigateway']


def _error(fn):
    """Call fn(); return the ClientError's (Error.Code, Error.Message). An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected NotFoundException, but GetVpcLink SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetVpcLink with a bogus vpcLinkId must fail with NotFoundException (overly-permissive check)."""
    ag = ctx.client("apigateway")
    code, message = _error(lambda: ag.get_vpc_link(vpcLinkId="bogusvpclink123"))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "Invalid Vpc Link identifier specified", f"unexpected message {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
