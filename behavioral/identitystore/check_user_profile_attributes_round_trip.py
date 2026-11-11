"""user-profile-attributes-round-trip."""
from __future__ import annotations

import time as _time

from behavioral_harness import tags

CHECK = "user-profile-attributes-round-trip"
GROUP = "data-plane"
SERVICES = ["identitystore"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """CreateUser with a full profile round-trips exactly through DescribeUser; DeleteUser then
    makes the user independently unreadable and unmutable."""
    identity_store_id = _get_identity_store_id(ctx)
    idstore = ctx.client("identitystore")

    user_name = ctx.unique_name("sim2real-behav-user-")
    display_name = "Jane Q. Behavioral"
    created = idstore.create_user(
        IdentityStoreId=identity_store_id,
        UserName=user_name,
        DisplayName=display_name,
        Name={"GivenName": "Jane", "FamilyName": "Behavioral", "MiddleName": "Q"},
        Emails=[{"Value": "jane.behavioral@example.com", "Type": "work", "Primary": True}],
        Addresses=[
            {
                "StreetAddress": "123 Test Street",
                "Locality": "Testville",
                "Region": "WA",
                "PostalCode": "98101",
                "Country": "US",
                "Type": "home",
                "Primary": True,
            }
        ],
        PhoneNumbers=[{"Value": "+1.555.010.0100", "Type": "mobile", "Primary": True}],
        Title="Principal Behavioral Engineer",
        PreferredLanguage="en-US",
        Locale="en-US",
        Timezone="America/Los_Angeles",
    )
    user_id = created["UserId"]
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: idstore.delete_user(IdentityStoreId=identity_store_id, UserId=user_id))
    )

    desc = idstore.describe_user(IdentityStoreId=identity_store_id, UserId=user_id)
    assert desc["UserName"] == user_name, f"UserName: expected {user_name!r}, got {desc.get('UserName')!r}"
    assert desc["DisplayName"] == display_name, (
        f"DisplayName: expected {display_name!r}, got {desc.get('DisplayName')!r}"
    )
    assert desc["Name"]["GivenName"] == "Jane", f"GivenName: expected 'Jane', got {desc['Name'].get('GivenName')!r}"
    assert desc["Name"]["FamilyName"] == "Behavioral", (
        f"FamilyName: expected 'Behavioral', got {desc['Name'].get('FamilyName')!r}"
    )
    assert desc["Name"]["MiddleName"] == "Q", f"MiddleName: expected 'Q', got {desc['Name'].get('MiddleName')!r}"

    emails = desc["Emails"]
    assert len(emails) == 1, f"Emails: expected 1 entry, got {len(emails)}"
    assert emails[0]["Value"] == "jane.behavioral@example.com", (
        f"Email value: expected 'jane.behavioral@example.com', got {emails[0].get('Value')!r}"
    )
    assert emails[0]["Type"] == "work", f"Email type: expected 'work', got {emails[0].get('Type')!r}"
    assert emails[0]["Primary"] is True, f"Email primary: expected True, got {emails[0].get('Primary')!r}"

    addresses = desc["Addresses"]
    assert len(addresses) == 1, f"Addresses: expected 1 entry, got {len(addresses)}"
    addr = addresses[0]
    assert addr["StreetAddress"] == "123 Test Street", (
        f"StreetAddress: expected '123 Test Street', got {addr.get('StreetAddress')!r}"
    )
    assert addr["Locality"] == "Testville", f"Locality: expected 'Testville', got {addr.get('Locality')!r}"
    assert addr["Region"] == "WA", f"Region: expected 'WA', got {addr.get('Region')!r}"
    assert addr["PostalCode"] == "98101", f"PostalCode: expected '98101', got {addr.get('PostalCode')!r}"
    assert addr["Country"] == "US", f"Country: expected 'US', got {addr.get('Country')!r}"
    assert addr["Type"] == "home", f"Address type: expected 'home', got {addr.get('Type')!r}"
    assert addr["Primary"] is True, f"Address primary: expected True, got {addr.get('Primary')!r}"

    phones = desc["PhoneNumbers"]
    assert len(phones) == 1, f"PhoneNumbers: expected 1 entry, got {len(phones)}"
    assert phones[0]["Value"] == "+1.555.010.0100", (
        f"Phone value: expected '+1.555.010.0100', got {phones[0].get('Value')!r}"
    )
    assert phones[0]["Type"] == "mobile", f"Phone type: expected 'mobile', got {phones[0].get('Type')!r}"
    assert phones[0]["Primary"] is True, f"Phone primary: expected True, got {phones[0].get('Primary')!r}"

    assert desc["Title"] == "Principal Behavioral Engineer", (
        f"Title: expected 'Principal Behavioral Engineer', got {desc.get('Title')!r}"
    )
    assert desc["PreferredLanguage"] == "en-US", (
        f"PreferredLanguage: expected 'en-US', got {desc.get('PreferredLanguage')!r}"
    )
    assert desc["Locale"] == "en-US", f"Locale: expected 'en-US', got {desc.get('Locale')!r}"
    assert desc["Timezone"] == "America/Los_Angeles", (
        f"Timezone: expected 'America/Los_Angeles', got {desc.get('Timezone')!r}"
    )

    idstore.delete_user(IdentityStoreId=identity_store_id, UserId=user_id)
    read_code, read_message = _error(lambda: idstore.describe_user(IdentityStoreId=identity_store_id, UserId=user_id))
    assert read_code == "ResourceNotFoundException", (
        f"post-delete DescribeUser: expected ResourceNotFoundException, got {read_code!r}"
    )
    assert read_message == "User not found", (
        f"post-delete DescribeUser: expected message 'User not found', got {read_message!r}"
    )
    mutate_code, mutate_message = _error(
        lambda: idstore.update_user(
            IdentityStoreId=identity_store_id,
            UserId=user_id,
            Operations=[{"AttributePath": "displayName", "AttributeValue": "ghost"}],
        )
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"post-delete UpdateUser: expected ResourceNotFoundException, got {mutate_code!r}"
    )
    assert mutate_message == "User not found", (
        f"post-delete UpdateUser: expected message 'User not found', got {mutate_message!r}"
    )


def _get_identity_store_id(ctx):
    """Discover or provision the account's IAM Identity Center identity store id.

    identitystore has no provisioning API of its own; sso-admin CreateInstance
    provisions an IAM Identity Center instance in a standalone account (AWS Organizations
    management accounts reject it). The instance is an account-wide singleton (one per
    account, across every region) and is left in place for reuse.
    """
    ssoadmin = ctx.client("sso-admin")
    instances = ssoadmin.list_instances().get("Instances", [])
    if instances:
        return instances[0]["IdentityStoreId"]

    from botocore.exceptions import ClientError

    try:
        created = ssoadmin.create_instance(Name=ctx.unique_name("sim2real-idc-"))
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        raise AssertionError(
            f"no IAM Identity Center instance exists and sso-admin CreateInstance was rejected "
            f"({code}: {exc.response['Error'].get('Message')}); identitystore requires a "
            "pre-existing instance that this check cannot provision in this account"
        ) from exc
    instance_arn = created["InstanceArn"]

    deadline = _time.monotonic() + 60
    while _time.monotonic() < deadline:
        for inst in ssoadmin.list_instances().get("Instances", []):
            if inst.get("InstanceArn") == instance_arn and inst.get("IdentityStoreId"):
                return inst["IdentityStoreId"]
        _time.sleep(2)
    raise AssertionError(
        "sso-admin CreateInstance succeeded but its IdentityStoreId never appeared via "
        "list_instances within 60s"
    )


def _ignore_not_found(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    """Call fn() and return the (code, message) of its ClientError; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected a ClientError but the call succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
