"""create-reusable-delegation-set-duplicate-caller-reference-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-reusable-delegation-set-duplicate-caller-reference-rejected"
GROUP = "delegation-set"
SERVICES = ["route53"]


def _error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delegation_set_ids_for(r53, caller_reference: str) -> set[str]:
    """Every reusable delegation set id whose CallerReference equals caller_reference."""
    ids: set[str] = set()
    kwargs: dict = {}
    while True:
        resp = r53.list_reusable_delegation_sets(**kwargs)
        for ds in resp["DelegationSets"]:
            if ds.get("CallerReference") == caller_reference:
                ids.add(ds["Id"])
        if not resp.get("IsTruncated"):
            return ids
        kwargs = {"Marker": resp["NextMarker"]}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateReusableDelegationSet with a CallerReference that a live delegation set already
    holds answers DelegationSetAlreadyCreated and creates nothing new, while the same call with
    a fresh CallerReference succeeds.
    """
    r53 = ctx.client("route53")
    caller_reference = ctx.unique_name("sim2real-behav-rds-")
    other_caller_reference = ctx.unique_name("sim2real-behav-rds2-")

    first = r53.create_reusable_delegation_set(CallerReference=caller_reference)
    first_id = first["DelegationSet"]["Id"]
    ctx.on_cleanup(lambda i=first_id: r53.delete_reusable_delegation_set(Id=i))
    assert first["DelegationSet"]["CallerReference"] == caller_reference, first["DelegationSet"]

    # Positive control: the delegation set we just created is really there.
    before_ids = _delegation_set_ids_for(r53, caller_reference)
    assert before_ids == {first_id}, (
        f"expected exactly {{{first_id!r}}} for {caller_reference!r} before the duplicate "
        f"attempt, got {before_ids!r}"
    )

    # Break exactly one thing: reuse the same CallerReference while the original still exists.
    err = _error(lambda: r53.create_reusable_delegation_set(CallerReference=caller_reference))
    assert err.get("Code") == "DelegationSetAlreadyCreated", (
        f"expected DelegationSetAlreadyCreated reusing CallerReference {caller_reference!r}, "
        f"got {err!r}"
    )
    assert err.get("Message") == (
        "A delegation set has already been created with the specified caller reference."
    ), err

    # The refused call created no second delegation set under that CallerReference.
    after_ids = _delegation_set_ids_for(r53, caller_reference)
    assert after_ids == before_ids, (
        f"the refused duplicate create left {after_ids!r} for {caller_reference!r}, "
        f"expected only the original {before_ids!r}"
    )

    # The legal neighbour: the identical call with a CallerReference no delegation set holds
    # succeeds — it is the reused reference that is refused, not the operation itself.
    second = r53.create_reusable_delegation_set(CallerReference=other_caller_reference)
    second_id = second["DelegationSet"]["Id"]
    ctx.on_cleanup(lambda i=second_id: r53.delete_reusable_delegation_set(Id=i))
    assert second_id != first_id, "the control delegation set must be a distinct resource"
    assert second["DelegationSet"]["CallerReference"] == other_caller_reference, (
        second["DelegationSet"]
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
