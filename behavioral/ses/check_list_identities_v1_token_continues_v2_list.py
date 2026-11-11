"""list-identities-v1-token-continues-v2-list."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-identities-v1-token-continues-v2-list"
GROUP = 'identity-v2'
SERVICES = ['ses']

_MAX_PAGES = 120


def _unique_domain(ctx, prefix='v1v2tok-') -> str:
    # RFC 2606 reserved domain only.
    return f"{ctx.unique_name('sim2real-behav-' + prefix)}.example.com"


def _walk_v2_from(v2, token):
    """Walk ListEmailIdentities starting from an already-minted token. Returns names in order."""
    names = []
    for _ in range(_MAX_PAGES):
        kwargs = {'NextToken': token} if token else {}
        resp = v2.list_email_identities(**kwargs)
        names.extend(item['IdentityName'] for item in resp.get('EmailIdentities') or [])
        token = resp.get('NextToken')
        if not token:
            return names
    raise AssertionError(f'account holds more than {_MAX_PAGES} pages of SESv2 email identities')


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A NextToken minted by v1 ListIdentities, handed to v2 ListEmailIdentities, continues the SAME
    underlying list rather than being refused or silently restarting it from page one.
    """
    v1 = ctx.client('ses')
    v2 = ctx.client('sesv2')

    mine = []
    for i in range(3):
        dom = _unique_domain(ctx, f'tok{i}-')
        v2.create_email_identity(EmailIdentity=dom)
        ctx.on_cleanup(lambda _d=dom: v2.delete_email_identity(EmailIdentity=_d))
        mine.append(dom)

    first = v1.list_identities(MaxItems=1)
    page1 = first.get('Identities') or []
    assert len(page1) == 1, f"v1 ListIdentities(MaxItems=1) returned {len(page1)} items, expected exactly 1: {page1!r}"
    page1_name = page1[0]
    token = first.get('NextToken')
    assert token, (
        f"v1 ListIdentities(MaxItems=1) returned no NextToken even though this account holds at "
        f"least {len(mine)} identities beyond page 1 -- MaxItems appears to be ignored"
    )

    # A continuation must not re-serve the item v1 already returned on page 1.
    v2_resp = v2.list_email_identities(NextToken=token)
    v2_names = [item['IdentityName'] for item in v2_resp.get('EmailIdentities') or []]
    assert page1_name not in v2_names, (
        f"v2 ListEmailIdentities(NextToken=<v1 token>) re-served {page1_name!r}, the identity v1 "
        f"already returned on page 1 -- the v1 token did not continue the list, it restarted it"
    )

    # The continuation must reach the rest of our identities, not merely skip the first item.
    rest = _walk_v2_from(v2, token)
    assert page1_name not in rest, (
        f"{page1_name!r} reappeared later in the v2 continuation walk: {rest!r}"
    )
    seen = {page1_name, *rest}
    missing = set(mine) - seen
    assert not missing, (
        f"identities created by this check never appeared in v1-page1 union v2-continuation: "
        f"{sorted(missing)}; seen={sorted(seen)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
