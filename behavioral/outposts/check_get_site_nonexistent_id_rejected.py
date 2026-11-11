"""get-site-nonexistent-id-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-site-nonexistent-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["outposts"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSite for a well-formed but nonexistent SiteId is rejected with NotFoundException,
    while the same call for a real, just-created site succeeds (positive control)."""
    outposts = ctx.client("outposts")

    bogus_site_id = "os-" + "0" * 17
    code, message = _error(lambda: outposts.get_site(SiteId=bogus_site_id))
    assert code == "NotFoundException", (
        f"expected GetSite on a well-formed but nonexistent SiteId to fail with "
        f"NotFoundException, got {code!r}"
    )
    assert message == f"siteId={bogus_site_id}", f"unexpected GetSite message: {message!r}"

    # Positive control: a real site is retrievable without error.
    real_name = ctx.unique_name("sim2real-outposts-site-")
    real_site_id = outposts.create_site(
        Name=real_name, Tags={"sim2real-check": CHECK}
    )["Site"]["SiteId"]
    ctx.on_cleanup(lambda: outposts.delete_site(SiteId=real_site_id))
    got = outposts.get_site(SiteId=real_site_id)["Site"]
    assert got["Name"] == real_name, (
        f"expected the positive control's GetSite to return Name={real_name!r}, "
        f"got {got.get('Name')!r}"
    )


def _error(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
