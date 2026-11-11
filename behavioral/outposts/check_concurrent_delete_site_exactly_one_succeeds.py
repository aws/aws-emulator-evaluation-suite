"""concurrent-delete-site-exactly-one-succeeds."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-delete-site-exactly-one-succeeds"
GROUP = "concurrency"
SERVICES = ["outposts"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Six concurrent DeleteSite calls on one site: at least one succeeds, every other fails with
    NotFoundException, and GetSite then fails with NotFoundException and the message "siteId=<id>".
    """
    outposts = ctx.client("outposts")
    site_id = outposts.create_site(
        Name=ctx.unique_name("sim2real-outposts-site-"),
        Tags={"sim2real-check": "concurrent-delete-site-exactly-one-succeeds"},
    )["Site"]["SiteId"]
    ctx.on_cleanup(lambda: _delete_ignoring_not_found(lambda: outposts.delete_site(SiteId=site_id)))

    def _delete():
        try:
            outposts.delete_site(SiteId=site_id)
            return ("ok", None)
        except Exception as err:  # noqa: BLE001
            code = getattr(err, "response", {}).get("Error", {}).get("Code")
            return ("error", code)

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda _: _delete(), range(6)))

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]
    assert successes, f"expected at least 1 successful delete, got none: {results}"
    # message varies: a losing racer reads either "siteId=<id>" or "SiteId=<id>" depending on
    # which internal check observed the deletion, so only the code is asserted for the racers.
    assert all(code == "NotFoundException" for _, code in failures), results

    code, message = _error(lambda: outposts.get_site(SiteId=site_id))
    assert code == "NotFoundException", f"expected NotFoundException from GetSite after delete, got {code!r}"
    assert message == f"siteId={site_id}", f"unexpected GetSite message after delete: {message!r}"


def _delete_ignoring_not_found(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


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
