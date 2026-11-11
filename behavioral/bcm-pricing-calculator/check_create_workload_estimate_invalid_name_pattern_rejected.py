"""create-workload-estimate-invalid-name-pattern-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-workload-estimate-invalid-name-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["bcm-pricing-calculator"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateWorkloadEstimate rejects a name violating the ^[a-zA-Z0-9-]+$ pattern; a valid name still works."""
    client = ctx.client("bcm-pricing-calculator")
    bad_name = "bad name!"

    try:
        leaked = client.create_workload_estimate(name=bad_name)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    else:
        # Accepting a name AWS refuses is a failure in its own right, not an error-code mismatch:
        # raise, but still clean up the created resource so it does not leak.
        ctx.on_cleanup(lambda: _delete_workload_estimate(client, leaked["id"]))
        raise AssertionError(f"expected ValidationException, but create_workload_estimate SUCCEEDED with {leaked!r}")
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = (
        "1 validation error detected: Value at 'name' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [a-zA-Z0-9-]+"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: no resource with the rejected name exists anywhere in the account's listing.
    seen_names = set()
    next_token = None
    for _ in range(200):
        kwargs = {"maxResults": 25}
        if next_token:
            kwargs["nextToken"] = next_token
        page = client.list_workload_estimates(**kwargs)
        seen_names.update(i["name"] for i in page["items"])
        next_token = page.get("nextToken")
        if not next_token:
            break
    assert bad_name not in seen_names, f"rejected name {bad_name!r} unexpectedly appeared in list_workload_estimates"

    # Positive control: a valid name succeeds.
    good_name = ctx.unique_name("sim2real-we-")
    created = client.create_workload_estimate(name=good_name, tags={"sim2real": CHECK})
    estimate_id = created["id"]
    ctx.on_cleanup(lambda: _delete_workload_estimate(client, estimate_id))
    assert created["name"] == good_name, f"expected {good_name!r}, got {created['name']!r}"

    # Independent read at the destination: the create response alone is not the terminal check.
    fetched = client.get_workload_estimate(identifier=estimate_id)
    assert fetched["name"] == good_name, f"expected {good_name!r}, got {fetched['name']!r}"


# ===== helpers =====
def _delete_workload_estimate(client, estimate_id):
    from botocore.exceptions import ClientError

    try:
        client.delete_workload_estimate(identifier=estimate_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
