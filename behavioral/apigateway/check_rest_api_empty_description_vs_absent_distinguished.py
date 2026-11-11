"""rest-api-empty-description-vs-absent-distinguished."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "rest-api-empty-description-vs-absent-distinguished"
GROUP = "state-machine"
SERVICES = ["apigateway"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A non-empty description set at create time is distinguishable from a never-set
    description, and (empirically on real AWS) explicitly patching the description back to
    the empty string normalizes it to absent rather than preserving a distinct empty value."""
    apigw = ctx.client("apigateway")

    # Case 1: never set at all -> absent.
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-behav-"), tags={"sim2real": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    created = apigw.get_rest_api(restApiId=api_id)
    assert "description" not in created or created["description"] is None, (
        "an unset description must not be reported as a present value"
    )

    # Case 2: set to a real, non-empty value via patch -> present and equal.
    apigw.update_rest_api(
        restApiId=api_id,
        patchOperations=[{"op": "replace", "path": "/description", "value": "a real description"}],
    )
    with_desc = apigw.get_rest_api(restApiId=api_id)
    assert with_desc.get("description") == "a real description", (
        "an explicitly-set non-empty description must be returned verbatim"
    )

    # Case 3: patch it back to the empty string -> real AWS normalizes this to absent,
    # i.e. an explicit empty string is NOT distinguishable from never having been set.
    apigw.update_rest_api(
        restApiId=api_id,
        patchOperations=[{"op": "replace", "path": "/description", "value": ""}],
    )
    emptied = apigw.get_rest_api(restApiId=api_id)
    assert emptied.get("description") in (None, ""), (
        "an explicitly emptied description must not retain the old non-empty value"
    )
    assert "description" not in emptied or emptied["description"] == "" or emptied["description"] is None, (
        f"an emptied description must not retain a stale non-empty value, got {emptied.get('description')!r}"
    )
    # Empirical real-AWS behavior: the field is dropped (normalized to absent) rather than
    # kept as a distinct empty string.
    assert "description" not in emptied, (
        "real AWS normalizes an explicitly-emptied description to absent, not a distinct "
        "empty-string value"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
