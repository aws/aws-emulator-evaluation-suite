"""list-baselines-maxresults-out-of-range-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-baselines-maxresults-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["controltower"]


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListBaselines rejects maxResults=1 (below the 4-100 range) on the service side with
    BadRequestException "Invalid request body", while maxResults=10 returns a baselines list."""
    from botocore.config import Config

    # botocore would reject maxResults=1 against the model's 4-100 range before it reaches the service.
    ct = ctx.client("controltower", config=Config(parameter_validation=False))

    code, message = _error(lambda: ct.list_baselines(maxResults=1))
    assert code == "BadRequestException", f"expected BadRequestException for maxResults=1, got {code}"
    assert message == "Invalid request body", (
        f"expected 'Invalid request body' for maxResults=1, got {message!r}"
    )

    # positive control: an in-range maxResults on the same operation must succeed
    ok = ct.list_baselines(maxResults=10)
    assert "baselines" in ok, f"expected a 'baselines' key in the response, got {sorted(ok)}"


def _error(fn):
    """``(code, message)`` of the rejection ``fn`` raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects maxResults=1, but the call SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
