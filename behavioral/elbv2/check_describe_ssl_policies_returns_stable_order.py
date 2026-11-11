"""describe-ssl-policies-returns-stable-order."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-ssl-policies-returns-stable-order"
GROUP = "ordering"
SERVICES = ["elbv2"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeSSLPolicies returns the full set of predefined SSL policies in the same,
    deterministic order across repeated calls (and across paginated fetches within a single
    call), which callers rely on for diffing and stable pagination."""
    elbv2 = ctx.client("elbv2")

    first = _list_all_ssl_policy_names(elbv2)
    second = _list_all_ssl_policy_names(elbv2)
    third = _list_all_ssl_policy_names(elbv2)
    paginated = _list_all_ssl_policy_names(elbv2, page_size=1)

    assert len(first) > 5, (
        f"expected more than 5 predefined SSL policies, got {len(first)}: {first}"
    )
    assert first == second, (
        f"expected identical order across repeated DescribeSSLPolicies calls, "
        f"got {first} then {second}"
    )
    assert second == third, (
        f"expected identical order across repeated DescribeSSLPolicies calls, "
        f"got {second} then {third}"
    )
    assert first == paginated, (
        f"expected the same order when forced through PageSize=1 pagination as a single "
        f"unpaginated call, got {first} unpaginated vs {paginated} paginated"
    )


def _list_all_ssl_policy_names(elbv2, page_size: int | None = None) -> list[str]:
    names: list[str] = []
    kwargs: dict[str, object] = {}
    if page_size is not None:
        kwargs["PageSize"] = page_size
    while True:
        resp = elbv2.describe_ssl_policies(**kwargs)
        names.extend(p["Name"] for p in resp["SslPolicies"])
        marker = resp.get("NextMarker")
        if not marker:
            return names
        kwargs = {"Marker": marker}
        if page_size is not None:
            kwargs["PageSize"] = page_size


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
