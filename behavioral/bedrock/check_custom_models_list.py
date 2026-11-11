"""custom-models-list."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "custom-models-list"
GROUP = 'custom_models'
SERVICES = ['bedrock']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListCustomModels returns modelSummaries, nameContains on an unused name matches no model of that
    name, modelStatus='Active' is accepted, and an out-of-enum modelStatus returns the exact enum
    ValidationException."""
    bc = ctx.client("bedrock")

    resp = bc.list_custom_models()
    assert "modelSummaries" in resp, (
        f"ListCustomModels response missing 'modelSummaries'. Keys: {list(resp.keys())}"
    )

    unused_name = ctx.unique_name("sim2real-custmodel-unused-")
    filtered = bc.list_custom_models(nameContains=unused_name)
    names = {e["modelName"] for e in filtered.get("modelSummaries", [])}
    assert unused_name not in names, (
        f"nameContains={unused_name!r} unexpectedly matched an existing model: {names}"
    )

    # Positive control: a valid modelStatus filter is accepted, so the negative below
    # is attributable to the specific bad value rather than every ListCustomModels call.
    control = bc.list_custom_models(modelStatus="Active")
    assert "modelSummaries" in control, (
        f"ListCustomModels(modelStatus='Active') missing 'modelSummaries'. Keys: {list(control.keys())}"
    )

    got = _error(lambda: bc.list_custom_models(modelStatus="not-a-real-status"))
    expected = (
        "ValidationException",
        "1 validation error detected: Value 'not-a-real-status' at 'modelStatus' failed to "
        "satisfy constraint: Member must satisfy enum value set: [Active, Creating, Failed]",
    )
    assert got == expected, (
        f"ListCustomModels(modelStatus=<invalid enum value>) expected {expected!r}, got {got!r}"
    )


def _error(fn):
    """The AWS error (code, message) fn raises; raises AssertionError if fn succeeds."""
    try:
        fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError("expected a ClientError, call unexpectedly succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
