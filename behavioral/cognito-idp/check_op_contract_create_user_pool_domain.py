"""op-contract-createUserPoolDomain."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-createUserPoolDomain"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateUserPoolDomain provisions a prefix domain that becomes ACTIVE and is
    resolvable via DescribeUserPoolDomain, and rejects re-creating a domain name that
    is already in use."""
    cognito = ctx.client("cognito-idp")
    pool = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-op-contract"},
    )["UserPool"]
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    domain = ctx.unique_name("sim2real-domain-").lower().replace("_", "-")
    cognito.create_user_pool_domain(Domain=domain, UserPoolId=pool_id)
    ctx.on_cleanup(lambda: cognito.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id))

    status = _poll_until(
        lambda: cognito.describe_user_pool_domain(Domain=domain)["DomainDescription"],
        lambda desc: desc.get("Status") == "ACTIVE",
        timeout_s=90,
        interval_s=3,
    )
    assert status["UserPoolId"] == pool_id, (
        f"expected domain bound to pool {pool_id}, got {status['UserPoolId']}"
    )
    assert status["Status"] == "ACTIVE", f"expected domain status ACTIVE, got {status['Status']}"

    # distinct error boundary: the same domain prefix is already in use
    err = _client_error(lambda: cognito.create_user_pool_domain(Domain=domain, UserPoolId=pool_id))
    assert err.get("Code") == "InvalidParameterException", f"expected InvalidParameterException, got {err!r}"
    want = "Domain already exists."
    assert err.get("Message") == want, f"expected message {want!r}, got {err.get('Message')!r}"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
