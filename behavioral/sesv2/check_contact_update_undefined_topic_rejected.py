"""contact-update-undefined-topic-rejected."""
from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags
CHECK = "contact-update-undefined-topic-rejected"
GROUP = 'overly-permissive'
SERVICES = ['sesv2']

@tags("resource:account-singleton:sesv2-contact-list", "axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Setting a topic preference for a topic not defined on the list MUST fail, must not
    change the contact's stored preferences, and must succeed once the topic is added to
    the list's definition."""
    ses = ctx.client('sesv2')
    list_name = ctx.unique_name('sim2real-behav-clist-badtopic-')
    ses.create_contact_list(ContactListName=list_name, Topics=[{'TopicName': 'defined', 'DisplayName': 'Defined', 'DefaultSubscriptionStatus': 'OPT_IN'}])
    ctx.on_cleanup(lambda _k=list_name: ses.delete_contact_list(ContactListName=_k))
    email = ctx.unique_name('sim2real-behav-contact-badtopic-') + '@example.com'
    ses.create_contact(ContactListName=list_name, EmailAddress=email)
    ctx.on_cleanup(lambda _k=(list_name, email): ses.delete_contact(ContactListName=_k[0], EmailAddress=_k[1]))

    ses.update_contact(ContactListName=list_name, EmailAddress=email, TopicPreferences=[{'TopicName': 'defined', 'SubscriptionStatus': 'OPT_OUT'}])
    positive = ses.get_contact(ContactListName=list_name, EmailAddress=email)
    positive_prefs = {p['TopicName']: p['SubscriptionStatus'] for p in positive.get('TopicPreferences', [])}
    assert positive_prefs.get('defined') == 'OPT_OUT', f'positive control failed: expected defined=OPT_OUT, got {positive_prefs}'

    err = _error(lambda: ses.update_contact(ContactListName=list_name, EmailAddress=email, TopicPreferences=[{'TopicName': 'not-defined-anywhere', 'SubscriptionStatus': 'OPT_IN'}]))
    expected = ('BadRequestException', f"List: {list_name} doesn't contain Topic: not-defined-anywhere")
    assert err == expected, f'expected {expected} for an undefined topic, got {err!r}'

    after_reject = ses.get_contact(ContactListName=list_name, EmailAddress=email)
    after_reject_prefs = {p['TopicName']: p['SubscriptionStatus'] for p in after_reject.get('TopicPreferences', [])}
    assert 'not-defined-anywhere' not in after_reject_prefs, f'rejected topic preference leaked into storage: {after_reject_prefs}'
    assert after_reject_prefs.get('defined') == 'OPT_OUT', f'positive-control preference was clobbered by the rejected call: {after_reject_prefs}'

    ses.update_contact_list(ContactListName=list_name, Topics=[{'TopicName': 'defined', 'DisplayName': 'Defined', 'DefaultSubscriptionStatus': 'OPT_IN'}, {'TopicName': 'not-defined-anywhere', 'DisplayName': 'Not Defined Anywhere', 'DefaultSubscriptionStatus': 'OPT_IN'}])
    ses.update_contact(ContactListName=list_name, EmailAddress=email, TopicPreferences=[{'TopicName': 'not-defined-anywhere', 'SubscriptionStatus': 'OPT_IN'}])
    restored = ses.get_contact(ContactListName=list_name, EmailAddress=email)
    restored_prefs = {p['TopicName']: p['SubscriptionStatus'] for p in restored.get('TopicPreferences', [])}
    assert restored_prefs.get('not-defined-anywhere') == 'OPT_IN', f'identical call did not succeed once the topic was defined on the list: {restored_prefs}'


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
