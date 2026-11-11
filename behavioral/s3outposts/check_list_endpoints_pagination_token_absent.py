"""list-endpoints-pagination-token-absent."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-endpoints-pagination-token-absent"
GROUP = "pagination"
SERVICES = ["s3outposts"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """When fewer endpoints exist than the requested page size, ListEndpoints omits NextToken
    (there is nothing more to page through)."""
    s3o = ctx.client("s3outposts")
    resp = s3o.list_endpoints(MaxResults=100)
    endpoints = resp["Endpoints"]
    if len(endpoints) >= 100:
        raise AssertionError(
            "this account already has >=100 s3outposts endpoints, so the 'no more pages' "
            "case this check targets cannot be distinguished from a genuine next page"
        )
    next_token = resp.get("NextToken")
    assert not next_token, (
        f"ListEndpoints returned {len(endpoints)} endpoints (< MaxResults=100) but still set "
        f"NextToken={next_token!r}; expected NextToken to be omitted when there is nothing more "
        "to page through"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
