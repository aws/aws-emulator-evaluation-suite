"""list-sites-includes-created-site."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-sites-includes-created-site"
GROUP = "state"
SERVICES = ["outposts"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly created site's ID appears in the paginated ListSites results for the account,
    and is gone from both ListSites and GetSite once deleted."""
    outposts = ctx.client("outposts")
    name = ctx.unique_name("sim2real-outposts-site-")
    site_id = outposts.create_site(
        Name=name, Tags={"sim2real-check": "list-sites-includes-created-site"}
    )["Site"]["SiteId"]
    ctx.on_cleanup(lambda: _delete_ignoring_not_found(lambda: outposts.delete_site(SiteId=site_id)))

    found = _find_in_pages(outposts, "list_sites", "Sites", "SiteId", site_id)
    assert found is not None, f"site {site_id} not found in ListSites"
    assert found["Name"] == name, f"expected Name {name!r} in ListSites entry, got {found['Name']!r}"

    outposts.delete_site(SiteId=site_id)
    code, message = _error(lambda: outposts.get_site(SiteId=site_id))
    assert code == "NotFoundException", f"expected NotFoundException from GetSite after delete, got {code!r}"
    assert message == f"siteId={site_id}", f"unexpected GetSite message after delete: {message!r}"

    still_there = _find_in_pages(outposts, "list_sites", "Sites", "SiteId", site_id)
    assert still_there is None, f"deleted site {site_id} still present in ListSites: {still_there}"


def _find_in_pages(client, method_name, items_key, id_key, target_id, max_pages=50):
    method = getattr(client, method_name)
    kwargs: dict = {}
    for _ in range(max_pages):
        resp = method(**kwargs)
        for item in resp.get(items_key, []):
            if item.get(id_key) == target_id:
                return item
        token = resp.get("NextToken")
        if not token:
            return None
        kwargs["NextToken"] = token
    return None


def _error(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_ignoring_not_found(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
