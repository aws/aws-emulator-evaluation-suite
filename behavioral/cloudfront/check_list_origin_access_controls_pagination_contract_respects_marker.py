"""list-origin-access-controls-pagination-contract-respects-marker."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-origin-access-controls-pagination-contract-respects-marker"
GROUP = "server-side"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListOriginAccessControls with MaxItems=1 must resume from the exact next item across
    repeated calls (using NextMarker), visiting every created OAC exactly once -- no
    duplication and no gaps."""
    cf = ctx.client("cloudfront")

    created_ids: set[str] = set()
    for _ in range(3):
        ref = ctx.unique_name("sim2real-oac-")
        oac = cf.create_origin_access_control(
            OriginAccessControlConfig={
                "Name": ref,
                "Description": "sim2real-behav cloudfront check",
                "SigningProtocol": "sigv4",
                "SigningBehavior": "always",
                "OriginAccessControlOriginType": "s3",
            }
        )["OriginAccessControl"]
        oac_id = oac["Id"]
        created_ids.add(oac_id)
        ctx.on_cleanup(
            lambda oid=oac_id: cf.delete_origin_access_control(Id=oid, IfMatch=_current_etag(cf, oid))
        )

    seen: list[str] = []
    marker = None
    for _ in range(10_000):  # hard upper bound so a broken NextMarker loop can't hang forever
        kwargs = {"MaxItems": "1"}  # CloudFront's legacy pagination API models MaxItems as a string
        if marker:
            kwargs["Marker"] = marker
        page = cf.list_origin_access_controls(**kwargs)["OriginAccessControlList"]
        items = page.get("Items", [])
        assert len(items) <= 1, f"MaxItems=1 but page returned {len(items)} items"
        seen.extend(item["Id"] for item in items)
        marker = page.get("NextMarker")
        if not marker:
            break

    assert len(seen) == len(set(seen)), f"pagination walk produced duplicate IDs: {seen}"
    missing = created_ids - set(seen)
    assert not missing, f"pagination walk skipped created origin access controls: {missing}"


def _current_etag(cf, oac_id: str) -> str:
    return cf.get_origin_access_control(Id=oac_id)["ETag"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
