"""create-stage-invalid-name-pattern-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-stage-invalid-name-pattern-rejected"
GROUP = "error-semantics"
SERVICES = ["ivs-realtime"]


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")



@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStage rejects a name containing characters outside ^[a-zA-Z0-9-_]*$."""
    ivs = ctx.client("ivs-realtime")

    bad_name = "not a valid name! (has spaces & punctuation)"
    error = _client_error(lambda: ivs.create_stage(name=bad_name))
    assert error.get("Code") == "ValidationException", error
    assert error.get("Message") == (
        "CreateStage.name does not match the required pattern ^[a-zA-Z0-9-_]*$"
    ), error

    # The rejected call must not have left behind a stage with that (invalid) name.
    names = [s.get("name") for s in ivs.list_stages()["stages"]]
    assert bad_name not in names

    # Positive control: a name that matches the allowed pattern succeeds.
    good_name = ctx.unique_name("sim2real-stage-")
    created = ivs.create_stage(name=good_name, tags={"team": "sim2real"})["stage"]
    ctx.on_cleanup(lambda: ivs.delete_stage(arn=created["arn"]))
    assert created["name"] == good_name, created["name"]

    # Independent read at the destination: the name persisted, not just echoed
    # back by the mutating call itself.
    fetched = ivs.get_stage(arn=created["arn"])["stage"]
    assert fetched["name"] == good_name, fetched["name"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
