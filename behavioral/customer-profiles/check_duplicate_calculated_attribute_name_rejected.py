"""duplicate-calculated-attribute-name-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "duplicate-calculated-attribute-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["customer-profiles"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a calculated attribute with a name that already exists is rejected; the original definition is untouched."""
    cp = ctx.client("customer-profiles")
    domain = ctx.unique_name("sim2real-cp-dom-")
    object_type = "Orders"
    attr_name = ctx.unique_name("s2r_cp_calc_").replace("-", "_")
    other_name = ctx.unique_name("s2r_cp_calc2_").replace("-", "_")
    details = {"Attributes": [{"Name": "Amount"}], "Expression": "{Orders.Amount}"}

    cp.create_domain(DomainName=domain, DefaultExpirationDays=30, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: cp.delete_domain(DomainName=domain)))

    cp.put_profile_object_type(
        DomainName=domain,
        ObjectTypeName=object_type,
        Description="orders",
        Fields={"Amount": {"ContentType": "NUMBER", "Source": "_source.amount", "Target": "_profile.Attributes.amount"}},
        Keys={"uniqueKey": [{"StandardIdentifiers": ["PROFILE", "UNIQUE"], "FieldNames": ["Amount"]}]},
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: cp.delete_profile_object_type(DomainName=domain, ObjectTypeName=object_type)
        )
    )

    cp.create_calculated_attribute_definition(
        DomainName=domain,
        CalculatedAttributeName=attr_name,
        AttributeDetails=details,
        Statistic="SUM",
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: cp.delete_calculated_attribute_definition(
                DomainName=domain, CalculatedAttributeName=attr_name
            )
        )
    )

    code, message = _error(
        lambda: cp.create_calculated_attribute_definition(
            DomainName=domain,
            CalculatedAttributeName=attr_name,
            AttributeDetails=details,
            Statistic="SUM",
        )
    )
    assert code == "BadRequestException", f"expected BadRequestException on duplicate name, got {code!r}"
    assert message == f"Calculated attribute definition with name {attr_name} already exists", (
        f"unexpected duplicate-name message: {message!r}"
    )

    # effect absent: exactly one definition with this name exists, not duplicated/overwritten twice.
    listed = cp.list_calculated_attribute_definitions(DomainName=domain)["Items"]
    matches = [i for i in listed if i["CalculatedAttributeName"] == attr_name]
    assert len(matches) == 1, f"expected exactly 1 definition named {attr_name}, found {len(matches)}: {listed}"

    # The name is taken, not permanently forbidden: after deleting the definition, the
    # identical create call succeeds.
    cp.delete_calculated_attribute_definition(DomainName=domain, CalculatedAttributeName=attr_name)
    deleted_code, deleted_message = _error(
        lambda: cp.get_calculated_attribute_definition(
            DomainName=domain, CalculatedAttributeName=attr_name
        )
    )
    assert deleted_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading deleted {attr_name}, got {deleted_code!r}"
    )
    assert deleted_message == f"Calculated attribute definition with name {attr_name} not found", (
        f"unexpected message reading deleted {attr_name}: {deleted_message!r}"
    )
    cp.create_calculated_attribute_definition(
        DomainName=domain,
        CalculatedAttributeName=attr_name,
        AttributeDetails=details,
        Statistic="SUM",
        Tags={"sim2real": CHECK},
    )
    restored = cp.get_calculated_attribute_definition(
        DomainName=domain, CalculatedAttributeName=attr_name
    )
    assert restored["CalculatedAttributeName"] == attr_name, (
        f"expected recreated definition {attr_name}, got {restored.get('CalculatedAttributeName')!r}"
    )

    # positive control: a different name succeeds normally.
    cp.create_calculated_attribute_definition(
        DomainName=domain,
        CalculatedAttributeName=other_name,
        AttributeDetails=details,
        Statistic="SUM",
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: cp.delete_calculated_attribute_definition(
                DomainName=domain, CalculatedAttributeName=other_name
            )
        )
    )
    got = cp.get_calculated_attribute_definition(
        DomainName=domain, CalculatedAttributeName=other_name
    )
    assert got["CalculatedAttributeName"] == other_name, (
        f"expected {other_name}, got {got.get('CalculatedAttributeName')!r}"
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
