"""list-contacts-topic-filter-semantics."""
from __future__ import annotations
import time

from behavioral_harness import tags
CHECK = "list-contacts-topic-filter-semantics"
GROUP = 'contact-list'
SERVICES = ['sesv2']

@tags("resource:account-singleton:sesv2-contact-list", "axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListContacts topic filtering returns exactly the contacts matching the filter.

    Data-plane depth: three contacts with different topic preferences, then
    assert the OPT_IN / OPT_OUT filtered projections are exactly right.
    """
    ses = ctx.client('sesv2')
    list_name = ctx.unique_name('sim2real-behav-clist-filter-')
    ses.create_contact_list(ContactListName=list_name, Topics=[{'TopicName': 'news', 'DisplayName': 'News', 'DefaultSubscriptionStatus': 'OPT_OUT'}], Tags=[{'Key': 'sim2real-behav', 'Value': 'clist-filter'}])
    ctx.on_cleanup(lambda _k=list_name: ses.delete_contact_list(ContactListName=_k))
    opted_in = ctx.unique_name('sim2real-behav-in-') + '@example.com'
    opted_out = ctx.unique_name('sim2real-behav-out-') + '@example.com'
    defaulted = ctx.unique_name('sim2real-behav-def-') + '@example.com'
    ses.create_contact(ContactListName=list_name, EmailAddress=opted_in, TopicPreferences=[{'TopicName': 'news', 'SubscriptionStatus': 'OPT_IN'}])
    ctx.on_cleanup(lambda _k=(list_name, opted_in): ses.delete_contact(ContactListName=_k[0], EmailAddress=_k[1]))
    ses.create_contact(ContactListName=list_name, EmailAddress=opted_out, TopicPreferences=[{'TopicName': 'news', 'SubscriptionStatus': 'OPT_OUT'}])
    ctx.on_cleanup(lambda _k=(list_name, opted_out): ses.delete_contact(ContactListName=_k[0], EmailAddress=_k[1]))
    ses.create_contact(ContactListName=list_name, EmailAddress=defaulted)
    ctx.on_cleanup(lambda _k=(list_name, defaulted): ses.delete_contact(ContactListName=_k[0], EmailAddress=_k[1]))
    _deadline = time.monotonic() + 30
    all_contacts = None
    while time.monotonic() < _deadline:
        all_contacts = ses.list_contacts(ContactListName=list_name)
        if {c['EmailAddress'] for c in all_contacts.get('Contacts', [])} >= {opted_in, opted_out, defaulted}:
            break
        time.sleep(2)
    else:
        raise AssertionError('condition not met within ' + str(30) + 's. Last result: ' + repr(all_contacts))
    emails = {c['EmailAddress'] for c in all_contacts['Contacts']}
    assert emails == {opted_in, opted_out, defaulted}, emails
    filtered_in = ses.list_contacts(ContactListName=list_name, Filter={'FilteredStatus': 'OPT_IN', 'TopicFilter': {'TopicName': 'news', 'UseDefaultIfPreferenceUnavailable': False}})
    in_emails = {c['EmailAddress'] for c in filtered_in.get('Contacts', [])}
    assert in_emails == {opted_in}, in_emails
    filtered_out = ses.list_contacts(ContactListName=list_name, Filter={'FilteredStatus': 'OPT_OUT', 'TopicFilter': {'TopicName': 'news', 'UseDefaultIfPreferenceUnavailable': True}})
    out_emails = {c['EmailAddress'] for c in filtered_out.get('Contacts', [])}
    assert out_emails == {opted_out, defaulted}, out_emails
if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
