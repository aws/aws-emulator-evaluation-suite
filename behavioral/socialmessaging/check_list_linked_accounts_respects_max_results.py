"""list-linked-accounts-respects-max-results."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-linked-accounts-respects-max-results"
GROUP = "state"
SERVICES = ["socialmessaging"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListLinkedWhatsAppBusinessAccounts with maxResults=1 returns at most one account per page
    and a non-empty string nextToken while pages remain, and paging to the end collects exactly
    the ids a maxResults=100 listing returns."""
    sm = ctx.client("socialmessaging")

    full_ids = {a["id"] for a in _list_all(sm, page_size=100)}
    total = len(full_ids)

    paged_ids = set()
    token = None
    for _ in range(total + 1):
        kwargs = {"maxResults": 1}
        if token is not None:
            kwargs["nextToken"] = token
        response = sm.list_linked_whatsapp_business_accounts(**kwargs)
        page = response.get("linkedAccounts", [])
        assert len(page) <= 1, f"expected at most 1 account per page, got {len(page)}"
        paged_ids.update(a["id"] for a in page)
        token = response.get("nextToken")
        if token is not None:
            assert isinstance(token, str) and len(token) >= 1, (
                f"expected a non-empty string nextToken, got {token!r}"
            )
        if token is None:
            break
    else:
        raise AssertionError(
            f"pagination with maxResults=1 did not terminate within {total + 1} pages"
        )

    assert token is None, "final maxResults=1 page unexpectedly still returned a nextToken"
    assert paged_ids == full_ids, (
        f"paging with maxResults=1 collected {sorted(paged_ids)}, expected the "
        f"account's own reported set {sorted(full_ids)}"
    )


def _list_all(sm, page_size):
    accounts = []
    token = None
    for _ in range(1000):
        kwargs = {"maxResults": page_size}
        if token is not None:
            kwargs["nextToken"] = token
        response = sm.list_linked_whatsapp_business_accounts(**kwargs)
        accounts.extend(response.get("linkedAccounts", []))
        token = response.get("nextToken")
        if token is None:
            return accounts
    raise AssertionError(
        "list_linked_whatsapp_business_accounts did not terminate pagination within 1000 pages"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
