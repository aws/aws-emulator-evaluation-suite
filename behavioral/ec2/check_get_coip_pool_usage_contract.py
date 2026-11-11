"""op-contract-get-coip-pool-usage."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-coip-pool-usage"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetCoipPoolUsage's DryRun permission check succeeds independently of pool
    existence, while a real call against a nonexistent pool id is rejected."""
    ec2 = ctx.client("ec2")

    # A well-formed but unallocated Ipv4PoolCoipId. A malformed id (wrong prefix/
    # length) draws InvalidPoolID.Malformed instead, which is a different boundary.
    bogus_pool_id = "ipv4pool-coip-0123456789abcdef0"

    # Success-path contract proxy: DryRun proves the request is well-formed and
    # authorized, independent of whether the pool actually exists.
    dry_run_code, dry_run_message = _error(
        lambda: ec2.get_coip_pool_usage(PoolId=bogus_pool_id, DryRun=True)
    )
    assert dry_run_code == "DryRunOperation", f"expected DryRunOperation, got {dry_run_code!r}"
    assert dry_run_message == _DRY_RUN_MESSAGE, (
        f"expected DryRun message {_DRY_RUN_MESSAGE!r}, got {dry_run_message!r}"
    )

    # Error boundary: without DryRun, a nonexistent pool id is rejected with the
    # specific not-found code, not merely "some error other than DryRunOperation".
    code, message = _error(lambda: ec2.get_coip_pool_usage(PoolId=bogus_pool_id))
    assert code == "InvalidPoolID.NotFound", (
        f"expected InvalidPoolID.NotFound for a nonexistent CoIP pool id, got {code!r}"
    )
    expected = f"The pool ID '{bogus_pool_id}' does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its error as (code, message). An unexpected SUCCESS raises rather than
    returning a falsy sentinel."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
