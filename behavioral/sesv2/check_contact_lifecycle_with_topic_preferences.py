"""contact-lifecycle-with-topic-preferences."""
from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "contact-lifecycle-with-topic-preferences"
GROUP = 'contact-list'
SERVICES = ['sesv2']

@tags("resource:account-singleton:sesv2-contact-list", "axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """create contact with topic preference -> get reflects it -> update flips it -> delete."""
    ses = ctx.client('sesv2')
    list_name = ctx.unique_name('sim2real-behav-clist-topics-')
    ses.create_contact_list(ContactListName=list_name, Topics=[{'TopicName': 'promos', 'DisplayName': 'Promotions', 'DefaultSubscriptionStatus': 'OPT_OUT'}])
    ctx.on_cleanup(lambda _k=list_name: ses.delete_contact_list(ContactListName=_k))
    email = ctx.unique_name('sim2real-behav-contact-') + '@example.com'
    ses.create_contact(ContactListName=list_name, EmailAddress=email, TopicPreferences=[{'TopicName': 'promos', 'SubscriptionStatus': 'OPT_IN'}])
    ctx.on_cleanup(lambda _k=(list_name, email): ses.delete_contact(ContactListName=_k[0], EmailAddress=_k[1]))
    got = ses.get_contact(ContactListName=list_name, EmailAddress=email)
    prefs = {p['TopicName']: p['SubscriptionStatus'] for p in got['TopicPreferences']}
    assert prefs.get('promos') == 'OPT_IN', prefs
    ses.update_contact(ContactListName=list_name, EmailAddress=email, TopicPreferences=[{'TopicName': 'promos', 'SubscriptionStatus': 'OPT_OUT'}])
    got_after = ses.get_contact(ContactListName=list_name, EmailAddress=email)
    prefs_after = {p['TopicName']: p['SubscriptionStatus'] for p in got_after['TopicPreferences']}
    assert prefs_after.get('promos') == 'OPT_OUT', prefs_after
    ses.delete_contact(ContactListName=list_name, EmailAddress=email)
    expected = ('NotFoundException', f"{email} doesn't exist in List.")
    err = _error(lambda: ses.get_contact(ContactListName=list_name, EmailAddress=email))
    assert err == expected, f'expected {expected}, got {err}'
    update_err = _error(lambda: ses.update_contact(ContactListName=list_name, EmailAddress=email, TopicPreferences=[{'TopicName': 'promos', 'SubscriptionStatus': 'OPT_IN'}]))
    assert update_err == expected, f'expected {expected} updating a deleted contact, got {update_err}'
    ses.create_contact(ContactListName=list_name, EmailAddress=email, TopicPreferences=[{'TopicName': 'promos', 'SubscriptionStatus': 'OPT_IN'}])
    recreated = ses.get_contact(ContactListName=list_name, EmailAddress=email)
    recreated_prefs = {p['TopicName']: p['SubscriptionStatus'] for p in recreated['TopicPreferences']}
    assert recreated_prefs.get('promos') == 'OPT_IN', f'recreated contact did not reflect fresh preference: {recreated_prefs}'


def _error(fn):
    """Return the (code, message) of the ClientError fn raises; raise if fn succeeds."""
    try:
        result = fn()
    except ClientError as _e:
        _err = _e.response.get('Error', {})
        return (_err.get('Code'), _err.get('Message'))
    raise AssertionError(f'expected a ClientError, the call succeeded with {result!r}')


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
