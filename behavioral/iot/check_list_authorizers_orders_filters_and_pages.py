"""list-authorizers-orders-filters-and-pages."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-authorizers-orders-filters-and-pages"
GROUP = 'listing-semantics'
SERVICES = ['iot']


def _ours(authorizers, prefix):
    return [a for a in authorizers if a["authorizerName"].startswith(prefix)]


def _list_all(iot, **kw):
    out = []
    marker = None
    while True:
        req = dict(kw)
        if marker:
            req["marker"] = marker
        resp = iot.list_authorizers(**req)
        out.extend(resp.get("authorizers", []))
        marker = resp.get("nextMarker")
        if not marker:
            break
    return out


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListAuthorizers defaults to newest-first, honours ascendingOrder and a status filter, and
    its marker-based pagination with pageSize=1 visits every item exactly once in that same order.
    """
    iot = ctx.client("iot")
    account = ctx.client("sts").get_caller_identity()["Account"]
    fn_arn = f"arn:aws:lambda:{ctx.region}:{account}:function:sim2real-behav-listauthz-fn"
    prefix = ctx.unique_name("sim2real-behav-listauthz-")
    first, second, third = f"{prefix}-1", f"{prefix}-2", f"{prefix}-3"

    for name in (first, second, third):
        iot.create_authorizer(
            authorizerName=name,
            authorizerFunctionArn=fn_arn,
            signingDisabled=True,
            tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        ctx.on_cleanup(lambda _n=name: iot.delete_authorizer(authorizerName=_n))
        ctx.on_cleanup(lambda _n=name: iot.update_authorizer(authorizerName=_n, status="INACTIVE"))

    iot.update_authorizer(authorizerName=second, status="ACTIVE")

    # Listings are scoped to this check's name prefix so concurrent runs cannot change the answer.
    newest_first = _ours(_list_all(iot), prefix)
    newest_names = [a["authorizerName"] for a in newest_first]
    assert newest_names == [third, second, first], (
        f"default order must be newest-first, got {newest_names!r}"
    )
    for summary in newest_first:
        expected_arn = f"arn:aws:iot:{ctx.region}:{account}:authorizer/{summary['authorizerName']}"
        assert summary["authorizerArn"] == expected_arn, (
            f"authorizerArn {summary['authorizerArn']!r} did not match {expected_arn!r}"
        )

    ascending_names = [a["authorizerName"] for a in _ours(_list_all(iot, ascendingOrder=True), prefix)]
    assert ascending_names == [first, second, third], (
        f"ascendingOrder=True must reverse to oldest-first, got {ascending_names!r}"
    )

    active_names = [a["authorizerName"] for a in _ours(_list_all(iot, status="ACTIVE"), prefix)]
    assert active_names == [second], f"status=ACTIVE must return only {second!r}, got {active_names!r}"

    inactive_names = [a["authorizerName"] for a in _ours(_list_all(iot, status="INACTIVE"), prefix)]
    assert inactive_names == [third, first], (
        f"status=INACTIVE must return [{third!r}, {first!r}] newest-first, got {inactive_names!r}"
    )

    # pageSize=1 pagination must visit the same ordered set, one authorizer at a time.
    paged_names = []
    marker = None
    pages = 0
    while True:
        req = {"pageSize": 1}
        if marker:
            req["marker"] = marker
        resp = iot.list_authorizers(**req)
        page = resp.get("authorizers", [])
        assert len(page) == 1, f"pageSize=1 must return exactly one item per page, got {len(page)}"
        paged_names.append(page[0]["authorizerName"])
        marker = resp.get("nextMarker")
        pages += 1
        assert pages < 1000, "pagination did not terminate within 1000 pages"
        if not marker:
            break
    assert marker is None, "the last page must carry no nextMarker"
    ours_paged = [n for n in paged_names if n.startswith(prefix)]
    assert ours_paged == [third, second, first], (
        f"paginated traversal must visit our authorizers in newest-first order, got {ours_paged!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
