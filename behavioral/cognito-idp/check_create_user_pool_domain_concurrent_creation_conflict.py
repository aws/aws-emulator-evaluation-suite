"""create-user-pool-domain-concurrent-creation-conflict."""
from __future__ import annotations

import threading
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-user-pool-domain-concurrent-creation-conflict"
GROUP = "concurrency"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Of several concurrent CreateUserPoolDomain calls for one domain name exactly one succeeds;
    the others answer InvalidParameterException "Domain already exists.", and the domain
    describes on its pool."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx)
    domain = ctx.unique_name("sim2real-dom-").lower().replace("_", "-")
    ctx.on_cleanup(lambda: _delete_domain_and_wait_gone(idp, domain, pool_id))

    n = 6
    calls = [
        (lambda: idp.create_user_pool_domain(Domain=domain, UserPoolId=pool_id))
        for _ in range(n)
    ]
    results = _race(calls)
    successes = [r for r in results if r[0]]
    failures = [r for r in results if not r[0]]
    assert len(successes) == 1, f"expected exactly one winner, got {len(successes)}"
    for _, code, message in failures:
        assert (code, message) == ("InvalidParameterException", "Domain already exists."), (
            f"expected each losing racer to get InvalidParameterException 'Domain already exists.', "
            f"got {code} {message!r}"
        )

    # Terminal read, independent of the racing CreateUserPoolDomain calls: confirm
    # the winner's domain is actually visible and usable via DescribeUserPoolDomain,
    # not just that its own response looked like success.
    description = _wait_for_domain_status(idp, domain, "ACTIVE", timeout_s=120)
    assert description["UserPoolId"] == pool_id, (
        f"expected domain {domain} to belong to {pool_id}, got {description['UserPoolId']}"
    )


def _race(calls):
    n = len(calls)
    barrier = threading.Barrier(n)
    results: list = [None] * n

    def _worker(i, fn):
        barrier.wait()
        try:
            fn()
            results[i] = (True, None, None)
        except ClientError as e:
            results[i] = (False, e.response["Error"]["Code"], e.response["Error"].get("Message"))

    threads = [threading.Thread(target=_worker, args=(i, fn)) for i, fn in enumerate(calls)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


def _ignore(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_domain_and_wait_gone(idp, domain, pool_id, timeout_s=20.0, interval_s=1.5):
    # DeleteUserPoolDomain returns before the binding is torn down, and DeleteUserPool fails while
    # it is in progress; wait until DescribeUserPoolDomain reports no bound pool so the pool delete
    # (registered earlier, run later) succeeds.
    _ignore(lambda: idp.delete_user_pool_domain(Domain=domain, UserPoolId=pool_id))
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            desc = idp.describe_user_pool_domain(Domain=domain).get("DomainDescription") or {}
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        if not desc.get("UserPoolId"):
            return
        time.sleep(interval_s)


def _wait_for_domain_status(idp, domain, status, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    description = None
    while time.monotonic() < deadline:
        try:
            description = idp.describe_user_pool_domain(Domain=domain)["DomainDescription"]
        except ClientError:
            description = None
        last = description.get("Status") if description else None
        if last == status:
            return description
        time.sleep(interval_s)
    raise AssertionError(f"domain {domain} never reached {status}, last saw {last!r}")


def _delete_pool_retrying(idp, pool_id, timeout_s=15.0, interval_s=1.5):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            idp.delete_user_pool(UserPoolId=pool_id)
            return
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _create_pool(ctx):
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _delete_pool_retrying(idp, pool_id))
    return pool_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
