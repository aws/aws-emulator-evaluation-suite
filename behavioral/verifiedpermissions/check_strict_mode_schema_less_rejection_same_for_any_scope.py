"""strict-mode-schema-less-rejection-same-for-any-scope."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "strict-mode-schema-less-rejection-same-for-any-scope"
GROUP = "overly-permissive"
SERVICES = ["verifiedpermissions"]

_SCHEMA = {
    "Workspace": {
        "entityTypes": {"Member": {}, "Doc": {}},
        "actions": {
            "access": {
                "appliesTo": {"principalTypes": ["Member"], "resourceTypes": ["Doc"]}
            }
        },
    }
}


def _refuse(fn):
    """The botocore error response ``fn`` raises; an unexpected success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A STRICT store with no schema refuses a static policy with the same error
    whether or not it names a principal type; PutSchema then lets a scoped one
    through, and a store made directly in OFF mode accepts the unconstrained one."""
    client = ctx.client("verifiedpermissions")

    strict_store = client.create_policy_store(
        validationSettings={"mode": "STRICT"}, tags={"sim2real-check": CHECK}
    )["policyStoreId"]
    ctx.on_cleanup(lambda: client.delete_policy_store(policyStoreId=strict_store))

    unconstrained = "permit(principal, action, resource);"
    principal_typed = 'permit(principal == Workspace::Member::"m1", action, resource);'

    refusal_unconstrained = _refuse(
        lambda: client.create_policy(
            policyStoreId=strict_store, definition={"static": {"statement": unconstrained}}
        )
    )
    refusal_principal_typed = _refuse(
        lambda: client.create_policy(
            policyStoreId=strict_store, definition={"static": {"statement": principal_typed}}
        )
    )

    expected_field_list = [
        {
            "path": "/definition",
            "message": "No schema present - automatically failing all validation.",
        }
    ]
    for label, refusal in (
        ("unconstrained", refusal_unconstrained),
        ("principal-typed", refusal_principal_typed),
    ):
        assert refusal["Error"]["Code"] == "ValidationException", (
            f"the {label} statement was refused with {refusal['Error']['Code']!r}, "
            f"expected 'ValidationException'"
        )
        assert refusal["Error"]["Message"] == "Invalid input", (
            f"the {label} statement's error message was {refusal['Error']['Message']!r}, "
            f"expected 'Invalid input'"
        )
        assert refusal.get("fieldList") == expected_field_list, (
            f"the {label} statement's fieldList was {refusal.get('fieldList')!r}, "
            f"expected {expected_field_list!r}"
        )

    assert refusal_unconstrained["Error"] == refusal_principal_typed["Error"], (
        f"the two statements produced different Error blocks: "
        f"{refusal_unconstrained['Error']!r} vs {refusal_principal_typed['Error']!r}"
    )
    assert refusal_unconstrained["fieldList"] == refusal_principal_typed["fieldList"], (
        f"the two statements produced different fieldLists: "
        f"{refusal_unconstrained['fieldList']!r} vs {refusal_principal_typed['fieldList']!r}"
    )

    stranded = client.list_policies(policyStoreId=strict_store)["policies"]
    assert stranded == [], (
        f"both refused create_policy calls left policies behind: {stranded!r}"
    )

    client.put_schema(policyStoreId=strict_store, definition={"cedarJson": json.dumps(_SCHEMA)})

    scoped = (
        'permit(principal == Workspace::Member::"m1", action == Workspace::Action::"access", '
        'resource == Workspace::Doc::"d1");'
    )
    scoped_policy_id = client.create_policy(
        policyStoreId=strict_store, definition={"static": {"statement": scoped}}
    )["policyId"]
    ctx.on_cleanup(
        lambda: client.delete_policy(policyStoreId=strict_store, policyId=scoped_policy_id)
    )

    fetched_scoped = client.get_policy(policyStoreId=strict_store, policyId=scoped_policy_id)
    assert fetched_scoped["policyId"] == scoped_policy_id, (
        f"after PutSchema, an independent get_policy read returned policyId "
        f"{fetched_scoped['policyId']!r}, expected {scoped_policy_id!r}"
    )
    assert fetched_scoped["definition"]["static"]["statement"] == scoped, (
        f"the read-back statement was {fetched_scoped['definition']['static']['statement']!r}, "
        f"expected {scoped!r}"
    )

    off_store = client.create_policy_store(
        validationSettings={"mode": "OFF"}, tags={"sim2real-check": CHECK}
    )["policyStoreId"]
    ctx.on_cleanup(lambda: client.delete_policy_store(policyStoreId=off_store))

    off_policy_id = client.create_policy(
        policyStoreId=off_store, definition={"static": {"statement": unconstrained}}
    )["policyId"]
    ctx.on_cleanup(lambda: client.delete_policy(policyStoreId=off_store, policyId=off_policy_id))

    fetched_off = client.get_policy(policyStoreId=off_store, policyId=off_policy_id)
    assert fetched_off["policyId"] == off_policy_id, (
        f"the OFF-mode store accepted the unconstrained statement but an independent "
        f"get_policy read returned policyId {fetched_off['policyId']!r}, expected "
        f"{off_policy_id!r}"
    )
    assert fetched_off["definition"]["static"]["statement"] == unconstrained, (
        f"the OFF-mode store's read-back statement was "
        f"{fetched_off['definition']['static']['statement']!r}, expected {unconstrained!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
