"""contact-create-unknown-topic-rejected-sibling-preferences-pinned."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = 'contact-create-unknown-topic-rejected-sibling-preferences-pinned'
GROUP = 'contacts-v2'
SERVICES = ['sesv2']


def expect_error(fn, code: str, message: str) -> None:
    """Assert ``fn`` raises exactly ``(code, message)``; raise if it unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response['Error']
        assert err['Code'] == code, f'expected error code {code!r}, got {err["Code"]!r}'
        assert err['Message'] == message, f'expected message {message!r}, got {err["Message"]!r}'
        return
    raise AssertionError(f'expected {code!r}, but the call succeeded with {result!r}')


def _reclaim_contact_list_singleton(ctx, ses) -> None:
    """Delete the account's one contact list, if any, and restore it exactly on cleanup."""
    existing = ses.list_contact_lists().get('ContactLists', [])
    assert len(existing) <= 1, f'expected at most one contact list per account, found {existing!r}'
    if not existing:
        return
    prior_name = existing[0]['ContactListName']
    prior = ses.get_contact_list(ContactListName=prior_name)
    ses.delete_contact_list(ContactListName=prior_name)
    restore_kwargs = {'ContactListName': prior_name}
    if prior.get('Topics'):
        restore_kwargs['Topics'] = prior['Topics']
    if prior.get('Description'):
        restore_kwargs['Description'] = prior['Description']
    if prior.get('Tags'):
        restore_kwargs['Tags'] = prior['Tags']
    ctx.on_cleanup(lambda: ses.create_contact_list(**restore_kwargs))


@tags("resource:account-singleton:sesv2-contact-list", "axis:rejection", "cap:c1",
      "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateContact rejects a topic preference naming a topic absent from the list and the
    contact is never created, while a sibling naming only a listed topic succeeds and GetContact
    pins its explicit preference and the list's other topic at its own default exactly.
    """
    ses = ctx.client('sesv2')
    _reclaim_contact_list_singleton(ctx, ses)

    list_name = ctx.unique_name('sim2real-behav-clist-')
    ses.create_contact_list(
        ContactListName=list_name,
        Topics=[
            {'TopicName': 'digest', 'DisplayName': 'Digest', 'DefaultSubscriptionStatus': 'OPT_IN'},
            {'TopicName': 'alerts', 'DisplayName': 'Alerts', 'DefaultSubscriptionStatus': 'OPT_OUT'},
        ],
    )
    ctx.on_cleanup(lambda: ses.delete_contact_list(ContactListName=list_name))

    # positive control: a preference naming a topic on the list succeeds, overriding its default.
    ses.create_contact(
        ContactListName=list_name,
        EmailAddress='reader@example.net',
        TopicPreferences=[{'TopicName': 'alerts', 'SubscriptionStatus': 'OPT_IN'}],
    )
    pinned = ses.get_contact(ContactListName=list_name, EmailAddress='reader@example.net')
    assert pinned['TopicPreferences'] == [{'TopicName': 'alerts', 'SubscriptionStatus': 'OPT_IN'}], (
        f"expected the explicit preference pinned exactly, got {pinned['TopicPreferences']!r}"
    )
    assert pinned['TopicDefaultPreferences'] == [{'TopicName': 'digest', 'SubscriptionStatus': 'OPT_IN'}], (
        f"expected the list's remaining topic at its own default, got {pinned['TopicDefaultPreferences']!r}"
    )

    _UNKNOWN_TOPIC = ('BadRequestException', f"List: {list_name} doesn't contain Topic: missing")
    expect_error(
        lambda: ses.create_contact(
            ContactListName=list_name,
            EmailAddress='ghost@example.net',
            TopicPreferences=[{'TopicName': 'missing', 'SubscriptionStatus': 'OPT_IN'}],
        ),
        *_UNKNOWN_TOPIC,
    )

    _CONTACT_ABSENT = ('NotFoundException', "ghost@example.net doesn't exist in List.")
    expect_error(
        lambda: ses.get_contact(ContactListName=list_name, EmailAddress='ghost@example.net'),
        *_CONTACT_ABSENT,
    )


if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
