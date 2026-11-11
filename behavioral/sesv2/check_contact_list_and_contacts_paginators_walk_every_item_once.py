"""contact-list-and-contacts-paginators-walk-every-item-once."""
from __future__ import annotations

from botocore.config import Config

from behavioral_harness import tags

CHECK = "contact-list-and-contacts-paginators-walk-every-item-once"
GROUP = 'contact-paging'
SERVICES = ['sesv2']

_MAX_PAGES = 60
_RETRY_CONFIG = Config(retries={'max_attempts': 10, 'mode': 'adaptive'})


def _create_contact_list(ctx, sesv2) -> str:
    """Create this check's contact list, first deleting any sim2real- list left behind.

    SESv2 allows exactly one contact list per account per region."""
    for existing in sesv2.list_contact_lists().get('ContactLists', []):
        if not existing['ContactListName'].startswith('sim2real-'):
            continue  # not a sim2real list: leave it
        sesv2.delete_contact_list(ContactListName=existing['ContactListName'])
    name = ctx.unique_name('sim2real-behav-cl-')
    sesv2.create_contact_list(ContactListName=name)
    ctx.on_cleanup(lambda: sesv2.delete_contact_list(ContactListName=name))
    return name


def _walk_contact_lists(sesv2, page_size):
    names, token = [], None
    for _ in range(_MAX_PAGES):
        kwargs = {'PageSize': page_size}
        if token is not None:
            kwargs['NextToken'] = token
        resp = sesv2.list_contact_lists(**kwargs)
        names.extend(cl['ContactListName'] for cl in resp.get('ContactLists') or [])
        token = resp.get('NextToken')
        if not token:
            return names
    raise AssertionError(f'more than {_MAX_PAGES} pages of contact lists at PageSize={page_size}')


def _walk_contacts(sesv2, list_name, page_size):
    """Walk ListContacts; return (addresses_in_order, page_count).

    AWS does not bound a ListContacts page to PageSize, so no per-page size is asserted."""
    addrs, pages, token = [], 0, None
    for _ in range(_MAX_PAGES):
        kwargs = {'ContactListName': list_name, 'PageSize': page_size}
        if token is not None:
            kwargs['NextToken'] = token
        resp = sesv2.list_contacts(**kwargs)
        addrs.extend(c['EmailAddress'] for c in resp.get('Contacts') or [])
        pages += 1
        token = resp.get('NextToken')
        if not token:
            return addrs, pages
    raise AssertionError(f'more than {_MAX_PAGES} pages of contacts at PageSize={page_size}')


@tags("resource:account-singleton:sesv2-contact-list", "axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListContactLists and ListContacts page-walks visit the created list and every contact exactly
    once, with no drops, though AWS does not bound each ListContacts page to PageSize.
    """
    sesv2 = ctx.client('sesv2', config=_RETRY_CONFIG)
    list_name = _create_contact_list(ctx, sesv2)

    addresses = {ctx.unique_name('sim2real-behav-contact-') + '@example.com' for _ in range(10)}
    for addr in addresses:
        sesv2.create_contact(ContactListName=list_name, EmailAddress=addr)
        ctx.on_cleanup(lambda _a=addr: sesv2.delete_contact(ContactListName=list_name, EmailAddress=_a))

    walked_lists = _walk_contact_lists(sesv2, 1)
    dup_lists = {n for n in walked_lists if walked_lists.count(n) > 1}
    assert not dup_lists, f"ListContactLists paginated walk returned duplicates: {sorted(dup_lists)}"
    assert list_name in walked_lists, (
        f"ListContactLists paginated walk never surfaced {list_name!r}: saw {len(walked_lists)} lists"
    )

    walked_contacts, page_count = _walk_contacts(sesv2, list_name, 2)
    assert page_count >= 2, (
        f"expected ListContacts to actually paginate {len(addresses)} contacts across more than one "
        f"page at PageSize=2; got exactly {page_count} page(s) -- PageSize appears to be ignored entirely"
    )
    dup_contacts = {a for a in walked_contacts if walked_contacts.count(a) > 1}
    assert not dup_contacts, f"ListContacts paginated walk returned duplicates: {sorted(dup_contacts)}"
    assert set(walked_contacts) == addresses, (
        f"ListContacts paginated walk disagrees with what was created: "
        f"missing={sorted(addresses - set(walked_contacts))} extra={sorted(set(walked_contacts) - addresses)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
