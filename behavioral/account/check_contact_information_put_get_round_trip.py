"""contact-information-put-get-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "contact-information-put-get-round-trip"
GROUP = "state"
SERVICES = ["account"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:account-contacts")
def run(ctx) -> None:
    """PutContactInformation with the required fields is retrievable verbatim via GetContactInformation."""
    account = ctx.client("account")

    original = account.get_contact_information()["ContactInformation"]
    ctx.on_cleanup(lambda: account.put_contact_information(ContactInformation=original))

    new_info = {
        "FullName": "Sim2Real Behavioral Tester",
        "AddressLine1": "123 Sim2Real Way",
        "City": "Seattle",
        "StateOrRegion": "WA",
        "PostalCode": "98101",
        "CountryCode": "US",
        "PhoneNumber": "+1 206 555 0100",
    }
    account.put_contact_information(ContactInformation=new_info)

    fetched = account.get_contact_information()["ContactInformation"]
    for key, value in new_info.items():
        assert fetched[key] == value, f"{key}: expected {value!r}, got {fetched.get(key)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
