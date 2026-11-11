"""contact-list-lifecycle."""
from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "contact-list-lifecycle"
GROUP = 'contact-list'
SERVICES = ['sesv2']

@tags("resource:account-singleton:sesv2-contact-list", "axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """create(with topic) -> get -> update description -> delete -> get(NotFound) -> update(NotFound)."""
    ses = ctx.client('sesv2')
    try:
        for _e in ses.list_contact_lists().get('ContactLists', []):
            if not _e['ContactListName'].startswith('sim2real-'):
                continue  # not a list this check created: leave it
            try:
                ses.delete_contact_list(ContactListName=_e['ContactListName'])
            except Exception:
                pass
    except Exception:
        pass
    list_name = ctx.unique_name('sim2real-behav-clist-')
    ses.create_contact_list(ContactListName=list_name, Topics=[{'TopicName': 'news', 'DisplayName': 'News', 'DefaultSubscriptionStatus': 'OPT_IN'}], Description='initial', Tags=[{'Key': 'sim2real', 'Value': 'contact-list-lifecycle'}])
    ctx.on_cleanup(lambda _k=list_name: _tolerate_missing(lambda: ses.delete_contact_list(ContactListName=_k)))
    got = ses.get_contact_list(ContactListName=list_name)
    assert got['Description'] == 'initial', f"expected Description='initial', got {got['Description']!r}"
    assert got['Topics'][0]['TopicName'] == 'news', f"expected Topics[0].TopicName='news', got {got['Topics'][0]['TopicName']!r}"
    ses.update_contact_list(ContactListName=list_name, Topics=[{'TopicName': 'news', 'DisplayName': 'News', 'DefaultSubscriptionStatus': 'OPT_IN'}], Description='updated')
    got_after = ses.get_contact_list(ContactListName=list_name)
    assert got_after['Description'] == 'updated', got_after['Description']
    ses.delete_contact_list(ContactListName=list_name)
    expected = ('NotFoundException', f"List with name: {list_name} doesn't exist.")
    err = _error(lambda: ses.get_contact_list(ContactListName=list_name))
    assert err == expected, f'expected {expected}, got {err}'
    update_err = _error(lambda: ses.update_contact_list(ContactListName=list_name, Description='post-delete'))
    assert update_err == expected, f'expected UpdateContactList on a deleted list to fail with {expected}, got {update_err!r}'


def _error(fn):
    """Return the (code, message) of the ClientError fn raises; raise if fn succeeds."""
    try:
        result = fn()
    except ClientError as _e:
        _err = _e.response.get('Error', {})
        return (_err.get('Code'), _err.get('Message'))
    raise AssertionError(f'expected a ClientError, the call succeeded with {result!r}')


def _tolerate_missing(fn):
    """Teardown: run fn, treating NotFoundException as already gone."""
    try:
        fn()
    except ClientError as _e:
        if _e.response.get('Error', {}).get('Code') != 'NotFoundException':
            raise


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
