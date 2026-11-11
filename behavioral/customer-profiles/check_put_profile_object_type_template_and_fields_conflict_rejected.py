"""put-profile-object-type-template-and-fields-conflict-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-profile-object-type-template-and-fields-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["customer-profiles"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutProfileObjectType rejects a request that mixes TemplateId with Fields/Keys (the API docs are explicit:
    you may specify Fields+Keys, or TemplateId, but not all three) with BadRequestException; TemplateId alone succeeds."""
    cp = ctx.client("customer-profiles")
    domain = ctx.unique_name("sim2real-cp-dom-")
    object_type = "CTR"

    cp.create_domain(DomainName=domain, DefaultExpirationDays=30)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: cp.delete_domain(DomainName=domain)))

    code, message = _error_code(
        lambda: cp.put_profile_object_type(
            DomainName=domain,
            ObjectTypeName=object_type,
            Description="CTR with conflicting template+fields",
            TemplateId="CTR-NoInferred",
            Fields={"phone": {"ContentType": "PHONE_NUMBER", "Source": "_source.phone", "Target": "_profile.PhoneNumber"}},
            Keys={"phoneKey": [{"StandardIdentifiers": ["PROFILE"], "FieldNames": ["phone"]}]},
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException for TemplateId+Fields/Keys conflict, got {code!r}"
    assert message == "Can't specify fields or keys together with a templateId", message

    # effect absent: the object type was not created by the rejected mixed request.
    not_found_code, not_found_message = _error_code(
        lambda: cp.get_profile_object_type(DomainName=domain, ObjectTypeName=object_type)
    )
    assert not_found_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after rejected PutProfileObjectType, got {not_found_code!r}"
    )
    assert not_found_message == f"ObjectType {object_type} not found", not_found_message

    # positive control: TemplateId alone (no Fields/Keys) succeeds normally.
    created = cp.put_profile_object_type(
        DomainName=domain,
        ObjectTypeName=object_type,
        Description="CTR",
        TemplateId="CTR-NoInferred",
    )
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: cp.delete_profile_object_type(DomainName=domain, ObjectTypeName=object_type)
        )
    )
    assert created["ObjectTypeName"] == object_type, (
        f"expected ObjectTypeName {object_type!r} in PutProfileObjectType response, got {created.get('ObjectTypeName')!r}"
    )

    got = cp.get_profile_object_type(DomainName=domain, ObjectTypeName=object_type)
    assert got["TemplateId"] == "CTR-NoInferred", (
        f"expected TemplateId 'CTR-NoInferred' on GetProfileObjectType, got {got.get('TemplateId')!r}"
    )


def _error_code(fn):
    """Call fn(); return its botocore (error code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

