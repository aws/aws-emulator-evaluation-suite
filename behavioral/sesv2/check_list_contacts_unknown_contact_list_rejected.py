"""list-contacts-unknown-contact-list-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-contacts-unknown-contact-list-rejected"
GROUP = 'contact-paging'
SERVICES = ['sesv2']


def _error(fn):
    try:
        resp = fn()
    except ClientError as exc:
        return exc.response.get('Error', {}).get('Code'), exc.response.get('Error', {}).get('Message')
    raise AssertionError(f'expected the call to be refused, but it succeeded with {resp!r}')


@tags("resource:account-singleton:sesv2-contact-list", "axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListContacts on a never-created contact list is rejected with NotFoundException, while the
    same call on a freshly created list succeeds and returns no contacts."""
    sesv2 = ctx.client('sesv2')

    never_created = ctx.unique_name('sim2real-behav-cl-ghost-')
    err = _error(lambda: sesv2.list_contacts(ContactListName=never_created))
    expected = ('NotFoundException', f"List with name: {never_created} doesn't exist.")
    assert err == expected, f"expected {expected!r} for an unknown contact list, got {err!r}"

    # SESv2 allows one contact list per account per region, so clear leftover sim2real- lists.
    for existing in sesv2.list_contact_lists().get('ContactLists', []):
        if not existing['ContactListName'].startswith('sim2real-'):
            continue
        sesv2.delete_contact_list(ContactListName=existing['ContactListName'])
    real_list = ctx.unique_name('sim2real-behav-cl-')
    sesv2.create_contact_list(ContactListName=real_list)
    ctx.on_cleanup(lambda: sesv2.delete_contact_list(ContactListName=real_list))

    resp = sesv2.list_contacts(ContactListName=real_list)
    assert resp.get('Contacts', []) == [], (
        f"expected a freshly created, empty contact list to list empty, got {resp.get('Contacts')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
