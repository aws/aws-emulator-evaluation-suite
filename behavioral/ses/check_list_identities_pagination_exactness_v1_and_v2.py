"""list-identities-pagination-exactness-v1-and-v2."""
from __future__ import annotations

CHECK = "list-identities-pagination-exactness-v1-and-v2"
GROUP = 'identity-v2'
SERVICES = ['ses']

from behavioral_harness import tags
from botocore.exceptions import ClientError

_MAX_PAGES = 120


def _client_error(fn) -> ClientError:
    try:
        fn()
    except ClientError as exc:
        return exc
    raise AssertionError('expected the call to be refused, but it succeeded')


def _unique_domain(ctx, prefix='page-') -> str:
    # RFC 2606 reserved domain only.
    return f"{ctx.unique_name('sim2real-behav-' + prefix)}.example.com"


def _walk_v2(ses, page_size):
    """Walk ListEmailIdentities, returning (names_in_order, pages). Raises AssertionError past the bound."""
    names, pages, token = [], [], None
    for _ in range(_MAX_PAGES):
        kwargs = {'PageSize': page_size}
        if token is not None:
            kwargs['NextToken'] = token
        resp = ses.list_email_identities(**kwargs)
        page = [item['IdentityName'] for item in resp.get('EmailIdentities') or []]
        pages.append(page)
        names.extend(page)
        token = resp.get('NextToken')
        if not token:
            return names, pages
    raise AssertionError(
        f'account holds more than {_MAX_PAGES} pages of SESv2 email identities at PageSize={page_size}; '
        'pagination exactness is not measurable without walking an unbounded list'
    )


def _walk_v1(ses, max_items):
    """Walk v1 ListIdentities, returning (names_in_order, pages). Raises AssertionError past the bound."""
    names, pages, token = [], [], None
    for _ in range(_MAX_PAGES):
        kwargs = {'MaxItems': max_items}
        if token is not None:
            kwargs['NextToken'] = token
        resp = ses.list_identities(**kwargs)
        page = list(resp.get('Identities') or [])
        pages.append(page)
        names.extend(page)
        token = resp.get('NextToken')
        if not token:
            return names, pages
    raise AssertionError(
        f'account holds more than {_MAX_PAGES} pages of v1 identities at MaxItems={max_items}'
    )


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """v1 and v2 identity pagination honors the page size, yields each own identity once, terminates
    and agrees with the unpaginated read; a forged NextToken is refused rather than served as page
    one, and the v1 IdentityType filter partitions domains from email addresses.
    """
    v2 = ctx.client('sesv2')
    v1 = ctx.client('ses')

    mine_domains = []
    for i in range(3):
        dom = _unique_domain(ctx, f'page{i}-')
        v2.create_email_identity(EmailIdentity=dom)
        ctx.on_cleanup(lambda _d=dom: v2.delete_email_identity(EmailIdentity=_d))
        mine_domains.append(dom)
    mine_email = f"sim2real-behav-page@{_unique_domain(ctx, 'pagemail-')}"
    v2.create_email_identity(EmailIdentity=mine_email)
    ctx.on_cleanup(lambda _e=mine_email: v2.delete_email_identity(EmailIdentity=_e))
    mine = set(mine_domains) | {mine_email}

    # --- v2: PageSize=1 walk ---
    walked, pages = _walk_v2(v2, 1)
    assert len(pages) >= len(mine), (
        f"PageSize=1 must produce at least one page per identity; got {len(pages)} pages for "
        f"{len(walked)} identities -- PageSize appears to be ignored"
    )
    for idx, page in enumerate(pages):
        assert len(page) <= 1, f"page {idx} returned {len(page)} items for PageSize=1: {page!r}"
    # Graded on this check's own identities only: others may be created or deleted mid-walk.
    dupes = sorted({n for n in walked if n in mine and walked.count(n) > 1})
    assert not dupes, f"paginated ListEmailIdentities returned duplicates across pages: {dupes}"
    missing = mine - set(walked)
    assert not missing, f"paginated walk dropped identities that exist: {sorted(missing)}"

    # The paginated walk and the single-shot read agree on this check's identities.
    single, single_pages = _walk_v2(v2, 1000)
    assert mine & set(single) == mine & set(walked), (
        'paginated and unpaginated ListEmailIdentities disagree; '
        f"only-paginated={sorted(mine & (set(walked) - set(single)))} "
        f"only-single={sorted(mine & (set(single) - set(walked)))}"
    )
    assert len(single_pages) >= 1

    # --- v2: a forged NextToken must be refused, not served as page one ---
    forged = 'c2ltMnJlYWwtZm9yZ2VkLW5leHQtdG9rZW4='
    try:
        resp = v2.list_email_identities(PageSize=1, NextToken=forged)
    except ClientError as exc:
        code = exc.response['Error']['Code']
        msg = exc.response['Error'].get('Message')
        assert code == 'BadRequestException', (
            f"a forged NextToken must be refused with BadRequestException, got {code!r}: {msg!r}"
        )
        expected_msg = f"Invalid NextToken <{forged}>."
        assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"
        # ListEmailIdentities models only BadRequestException/TooManyRequestsException, not
        # InvalidNextTokenException.
    else:
        raise AssertionError(
            'a forged NextToken was silently accepted and served as a page -- an opaque cursor that is '
            f"never validated lets a caller silently restart the list: got {len(resp.get('EmailIdentities') or [])} "
            f"items and NextToken={resp.get('NextToken')!r}"
        )

    # --- v1: MaxItems=1 walk over the same store ---
    v1_walked, v1_pages = _walk_v1(v1, 1)
    for idx, page in enumerate(v1_pages):
        assert len(page) <= 1, f"v1 page {idx} returned {len(page)} items for MaxItems=1: {page!r}"
    v1_dupes = sorted({n for n in v1_walked if n in mine and v1_walked.count(n) > 1})
    assert not v1_dupes, f"v1 paginated ListIdentities returned duplicates: {v1_dupes}"
    v1_missing = mine - set(v1_walked)
    assert not v1_missing, f"v1 paginated walk dropped v2-created identities: {sorted(v1_missing)}"

    # --- v1: the IdentityType filter must partition, not merely subset ---
    domains_only = set(_walk_v1_filtered(v1, 'Domain'))
    emails_only = set(_walk_v1_filtered(v1, 'EmailAddress'))
    for dom in mine_domains:
        assert dom in domains_only, f"{dom!r} missing from ListIdentities(IdentityType='Domain')"
        assert dom not in emails_only, (
            f"{dom!r} is a domain identity and must not appear under IdentityType='EmailAddress'"
        )
    assert mine_email in emails_only, (
        f"{mine_email!r} missing from ListIdentities(IdentityType='EmailAddress')"
    )
    assert mine_email not in domains_only, (
        f"{mine_email!r} is an email identity and must not appear under IdentityType='Domain'"
    )


def _walk_v1_filtered(ses, identity_type):
    names, token = [], None
    for _ in range(_MAX_PAGES):
        kwargs = {'IdentityType': identity_type, 'MaxItems': 1000}
        if token is not None:
            kwargs['NextToken'] = token
        resp = ses.list_identities(**kwargs)
        names.extend(resp.get('Identities') or [])
        token = resp.get('NextToken')
        if not token:
            return names
    raise AssertionError(f'more than {_MAX_PAGES} pages of v1 {identity_type} identities')


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
