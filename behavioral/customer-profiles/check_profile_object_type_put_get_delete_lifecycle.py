"""profile-object-type-put-get-delete-lifecycle."""
from __future__ import annotations


from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "profile-object-type-put-get-delete-lifecycle"
GROUP = "state"
SERVICES = ["customer-profiles"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutProfileObjectType persists Fields/Description; DeleteProfileObjectType removes it (GetProfileObjectType 404s)."""
    cp = ctx.client("customer-profiles")
    domain = ctx.unique_name("sim2real-cp-dom-")
    object_type = ctx.unique_name("s2r_cp_ot_").replace("-", "_")

    cp.create_domain(
        DomainName=domain,
        DefaultExpirationDays=30,
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-cp-dom"},
    )
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: cp.delete_domain(DomainName=domain)))

    cp.put_profile_object_type(
        DomainName=domain,
        ObjectTypeName=object_type,
        Description="order records for behavioral check",
        Fields={
            "Amount": {"ContentType": "NUMBER", "Source": "_source.amount", "Target": "_profile.Attributes.amount"},
            "order_id": {"ContentType": "STRING", "Source": "_source.order_id", "Target": "_profile.Attributes.order_id"},
        },
        Keys={"orderKey": [{"StandardIdentifiers": ["PROFILE", "UNIQUE"], "FieldNames": ["order_id"]}]},
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-cp-ot"},
    )
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: cp.delete_profile_object_type(DomainName=domain, ObjectTypeName=object_type)
        )
    )

    got = cp.get_profile_object_type(DomainName=domain, ObjectTypeName=object_type)
    assert got["ObjectTypeName"] == object_type, f"expected ObjectTypeName {object_type!r}, got {got['ObjectTypeName']!r}"
    assert got["Description"] == "order records for behavioral check", (
        f"expected Description 'order records for behavioral check', got {got['Description']!r}"
    )
    assert got["Fields"]["Amount"]["ContentType"] == "NUMBER", (
        f"expected Fields.Amount.ContentType 'NUMBER', got {got['Fields']['Amount']['ContentType']!r}"
    )

    cp.delete_profile_object_type(DomainName=domain, ObjectTypeName=object_type)
    code, message = _error(
        lambda: cp.get_profile_object_type(DomainName=domain, ObjectTypeName=object_type)
    )
    assert code == "ResourceNotFoundException", (
        f"expected GetProfileObjectType on a deleted type to 404 with ResourceNotFoundException, got {code!r}"
    )
    assert message == f"ObjectType {object_type} not found", (
        f"unexpected GetProfileObjectType message for deleted type {object_type!r}: {message!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
