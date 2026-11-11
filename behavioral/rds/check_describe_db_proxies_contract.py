"""describe-db-proxies-contract."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-db-proxies-contract"
GROUP = 'proxy'
SERVICES = ['rds']


def _rejection(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeDBProxies without a filter returns a list, and an unknown DBProxyName is rejected with
    DBProxyNotFoundFault rather than answering empty."""
    rds = ctx.client("rds")
    resp = rds.describe_db_proxies()
    assert "DBProxies" in resp, f"expected a DBProxies key, got keys={sorted(resp)}"
    assert isinstance(resp["DBProxies"], list), (
        f"expected DBProxies to be a list, got {type(resp['DBProxies'])!r}"
    )

    bogus_proxy = ctx.unique_name("sim2real-behav-proxy-missing-")
    err = _rejection(lambda: rds.describe_db_proxies(DBProxyName=bogus_proxy))
    assert err.get("Code") == "DBProxyNotFoundFault", f"unexpected error: {err}"
    assert err.get("Message") == f"DBProxy '{bogus_proxy}' not found.", (
        f"unexpected DBProxyNotFoundFault message: {err}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
