"""op-contract-get-associated-ipv6-pool-cidrs."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-get-associated-ipv6-pool-cidrs"
GROUP = "error-semantics"
SERVICES = ["ec2"]

# The exact message EC2 returns for every DryRun call the caller is authorised for.
_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetAssociatedIpv6PoolCidrs with DryRun on a well-formed pool id fails with DryRunOperation and
    the standard message; a malformed pool id fails with InvalidIpv6PoolID.Malformed and its exact
    message; an IPv6 pool the account already owns returns a list of associations."""
    ec2 = ctx.client("ec2")

    # --- success-path contract: DryRun on a syntactically valid pool id ---
    code, message = _error(lambda: ec2.get_associated_ipv6_pool_cidrs(
        PoolId="ipv6pool-ec2-0123456789abcdef0", DryRun=True
    ))
    assert code == "DryRunOperation", code
    assert message == _DRY_RUN_MESSAGE, message

    # Bonus: if the account genuinely owns a BYOIP IPv6 pool, exercise the real data path.
    pools = ec2.describe_ipv6_pools().get("Ipv6Pools", [])
    if pools:
        pool_id = pools[0]["PoolId"]
        resp = ec2.get_associated_ipv6_pool_cidrs(PoolId=pool_id)
        assoc = resp["Ipv6CidrAssociations"]
        assert isinstance(assoc, list), f"expected a list, got {assoc!r}"

    # --- error boundary: malformed (non-EC2-shaped) pool id ---
    code, message = _error(lambda: ec2.get_associated_ipv6_pool_cidrs(PoolId="not-a-real-pool-id"))
    assert code == "InvalidIpv6PoolID.Malformed", code
    assert message == "The ipv6pool-ec2 ID 'not-a-real-pool-id' is malformed", message


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn() and return the (code, message) of the ClientError it raises. A call
    that succeeds raises AssertionError, because an emulator accepting what real AWS
    refuses must not read as a mere code mismatch."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
