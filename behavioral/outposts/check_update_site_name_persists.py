"""update-site-name-persists."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-site-name-persists"
GROUP = "state"
SERVICES = ["outposts"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateSite changes the site's Name/Description/Notes and GetSite reflects the new values."""
    outposts = ctx.client("outposts")
    original_name = ctx.unique_name("sim2real-outposts-site-")
    site_id = outposts.create_site(
        Name=original_name, Tags={"sim2real-check": "update-site-name-persists"}
    )["Site"]["SiteId"]
    ctx.on_cleanup(lambda: outposts.delete_site(SiteId=site_id))

    updated_name = ctx.unique_name("sim2real-outposts-site-renamed-")
    outposts.update_site(
        SiteId=site_id,
        Name=updated_name,
        Description="renamed by behavioral check",
        Notes="notes updated by behavioral check",
    )

    got = outposts.get_site(SiteId=site_id)["Site"]
    assert got["Name"] == updated_name, f"expected {updated_name!r}, got {got['Name']!r}"
    assert got["Name"] != original_name, f"name did not change from {original_name!r}"
    assert got["Description"] == "renamed by behavioral check", (
        f"expected 'renamed by behavioral check', got {got['Description']!r}"
    )
    assert got["Notes"] == "notes updated by behavioral check", (
        f"expected 'notes updated by behavioral check', got {got['Notes']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
