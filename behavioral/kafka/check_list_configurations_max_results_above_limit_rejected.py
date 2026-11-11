"""list-configurations-max-results-above-limit-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-configurations-max-results-above-limit-rejected"
GROUP = 'overly-permissive'
SERVICES = ['kafka']

# The shared MaxResults shape in the kafka model is {"type": "integer", "min": 1, "max": 100}.
# botocore.validate's VALIDATED_METADATA_ATTRS is {required, min, document, union}, so `min`
# is enforced client-side (MaxResults=0 never reaches the service -- that case belongs in a
# wire fixture) while `max` is NOT: MaxResults=101 is serialised and
# sent, and the 400 is entirely the service's decision.
_MAX_RESULTS_LIMIT = 100


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListConfigurations accepts MaxResults=100 but fails MaxResults=101 with BadRequestException 400 "One
    or more of the parameters are not valid." and no NextToken or Configurations, and legal paging works
    afterwards."""
    msk = ctx.client("kafka")

    # --- control: the boundary value is legal ---------------------------------------
    at_limit = msk.list_configurations(MaxResults=_MAX_RESULTS_LIMIT)
    assert isinstance(at_limit.get("Configurations", []), list), at_limit
    assert len(at_limit.get("Configurations", [])) <= _MAX_RESULTS_LIMIT, (
        f"MaxResults={_MAX_RESULTS_LIMIT} returned "
        f"{len(at_limit.get('Configurations', []))} items"
    )

    # --- break exactly one thing: one past the modeled maximum -----------------------
    over = _MAX_RESULTS_LIMIT + 1
    try:
        resp = msk.list_configurations(MaxResults=over)
        raise AssertionError(
            f"expected MaxResults={over} to be rejected, but it succeeded: {resp}"
        )
    except ClientError as exc:
        body = exc.response
        code = body.get("Error", {}).get("Code")
        status = body.get("ResponseMetadata", {}).get("HTTPStatusCode")
        assert code == "BadRequestException", (
            f"MaxResults={over} exceeds the modeled maximum of {_MAX_RESULTS_LIMIT} and must be "
            f"BadRequestException, not clamped; got {code} (HTTP {status})"
        )
        assert status == 400, f"expected HTTP 400 for MaxResults={over}, got {status}"
        message = body.get("Error", {}).get("Message")
        assert message == "One or more of the parameters are not valid.", (
            f"MaxResults={over}: unexpected BadRequestException message {message!r}"
        )

        # --- the effect must be absent: no page, no cursor ---------------------------
        assert "NextToken" not in body, (
            f"the rejected ListConfigurations still handed back a NextToken: "
            f"{body.get('NextToken')!r}"
        )
        assert "Configurations" not in body, (
            f"the rejected ListConfigurations still returned a page: {body.get('Configurations')}"
        )

    # --- the control case must still work --------------------------------------------
    after = msk.list_configurations(MaxResults=1)
    assert isinstance(after.get("Configurations", []), list), after
    assert len(after.get("Configurations", [])) <= 1, after


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
