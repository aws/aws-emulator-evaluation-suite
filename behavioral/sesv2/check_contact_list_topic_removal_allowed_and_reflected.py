"""contact-list-topic-removal-allowed-and-reflected."""
from __future__ import annotations

from behavioral_harness import tags
CHECK = "contact-list-topic-removal-allowed-and-reflected"
GROUP = 'contact-list'
SERVICES = ['sesv2']

@tags("resource:account-singleton:sesv2-contact-list", "axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateContactList may drop a topic a contact still has a preference for; the set is replaced.
    The dropped preference vanishes from GetContact and does not return when the topic is re-added.
    """
    ses = ctx.client('sesv2')
    list_name = ctx.unique_name('sim2real-behav-clist-inuse-')
    ses.create_contact_list(ContactListName=list_name, Topics=[{'TopicName': 'still_used', 'DisplayName': 'Still Used', 'DefaultSubscriptionStatus': 'OPT_IN'}])
    ctx.on_cleanup(lambda _k=list_name: ses.delete_contact_list(ContactListName=_k))
    email = ctx.unique_name('sim2real-behav-contact-inuse-') + '@example.com'
    ses.create_contact(ContactListName=list_name, EmailAddress=email, TopicPreferences=[{'TopicName': 'still_used', 'SubscriptionStatus': 'OPT_OUT'}])
    ctx.on_cleanup(lambda _k=(list_name, email): ses.delete_contact(ContactListName=_k[0], EmailAddress=_k[1]))
    ses.update_contact_list(ContactListName=list_name, Topics=[{'TopicName': 'unrelated', 'DisplayName': 'Unrelated', 'DefaultSubscriptionStatus': 'OPT_OUT'}])
    got = ses.get_contact_list(ContactListName=list_name)
    topics = {t['TopicName'] for t in got.get('Topics', [])}
    assert topics == {'unrelated'}, topics
    contact = ses.get_contact(ContactListName=list_name, EmailAddress=email)
    assert contact['EmailAddress'] == email, contact['EmailAddress']
    prefs = {p['TopicName']: p['SubscriptionStatus'] for p in contact.get('TopicPreferences', [])}
    assert 'still_used' not in prefs, f'preference for a topic no longer on the list should not be echoed back: {prefs}'
    ses.update_contact_list(ContactListName=list_name, Topics=[{'TopicName': 'unrelated', 'DisplayName': 'Unrelated', 'DefaultSubscriptionStatus': 'OPT_OUT'}, {'TopicName': 'still_used', 'DisplayName': 'Still Used', 'DefaultSubscriptionStatus': 'OPT_IN'}])
    got2 = ses.get_contact_list(ContactListName=list_name)
    topics2 = {t['TopicName'] for t in got2.get('Topics', [])}
    assert topics2 == {'unrelated', 'still_used'}, topics2
    contact2 = ses.get_contact(ContactListName=list_name, EmailAddress=email)
    prefs2 = {p['TopicName']: p['SubscriptionStatus'] for p in contact2.get('TopicPreferences', [])}
    assert 'still_used' not in prefs2, f'a topic preference dropped by removal does not come back merely because the topic is re-added to the list: {prefs2}'
if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
