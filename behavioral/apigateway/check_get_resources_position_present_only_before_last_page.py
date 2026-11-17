"""get-resources-position-present-only-before-last-page."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-resources-position-present-only-before-last-page"
GROUP = "pagination"
SERVICES = ["apigateway"]


def _teardown(undo, *not_found: str):
    """Cleanup running undo(); only the resource's own not_found codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetResources carries `position` on every page a further page follows, and omits it on
    the page that ends the collection; a limit exceeding the resource count returns all of
    them with no `position`."""
    apigw = ctx.client("apigateway")

    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-apigw-res-"),
        endpointConfiguration={"types": ["REGIONAL"]},
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(_teardown(lambda: apigw.delete_rest_api(restApiId=api_id), "NotFoundException"))

    root_id = apigw.get_resources(restApiId=api_id)["items"][0]["id"]
    child_ids = [
        apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart=part)["id"]
        for part in ("zulu", "alpha", "mike", "bravo")
    ]
    expected_ids = {root_id, *child_ids}

    pages = []
    position = None
    for _ in range(200):  # at most 200 pages: a position that never runs out fails instead of looping
        kwargs = {"restApiId": api_id, "limit": 1}
        if position:
            kwargs["position"] = position
        resp = apigw.get_resources(**kwargs)
        pages.append(resp)
        position = resp.get("position")
        if not position:
            break
    else:
        raise AssertionError("GetResources paginated 200 pages of limit=1 without exhausting position")

    assert len(pages) == len(expected_ids), (
        f"expected {len(expected_ids)} pages of 1 item each, got {len(pages)}"
    )
    for i, page in enumerate(pages[:-1]):
        assert page.get("position"), (
            f"page {i} of {len(pages)} is followed by another page but carries no position: {page!r}"
        )
    assert not pages[-1].get("position"), (
        f"the page that ends the collection still carries a position: {pages[-1]!r}"
    )

    seen_ids = [item["id"] for page in pages for item in page["items"]]
    assert set(seen_ids) == expected_ids, f"expected ids {expected_ids}, got {set(seen_ids)}"
    assert len(seen_ids) == len(expected_ids), f"duplicate or missing entries in the walk: {seen_ids!r}"

    oversized = apigw.get_resources(restApiId=api_id, limit=500)
    assert "position" not in oversized, (
        f"a limit (500) larger than the {len(expected_ids)} resources present still carried a "
        f"position: {oversized!r}"
    )
    oversized_ids = {item["id"] for item in oversized["items"]}
    assert oversized_ids == expected_ids, f"expected ids {expected_ids}, got {oversized_ids}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
