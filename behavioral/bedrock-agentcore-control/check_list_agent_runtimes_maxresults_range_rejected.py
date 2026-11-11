"""list-agent-runtimes-maxresults-range-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-agent-runtimes-maxresults-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListAgentRuntimes sent maxResults=0 (client-side validation off) is refused by the service with
    ValidationException and the exact range message, while maxResults=5 returns agentRuntimes."""
    from botocore.config import Config

    control = ctx.client("bedrock-agentcore-control", config=Config(parameter_validation=False))

    code, message = _error(lambda: control.list_agent_runtimes(maxResults=0))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = (
        "1 validation error detected: Value '0' at 'maxResults' failed to satisfy constraint: "
        "Member must have value greater than or equal to 1"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    ok_resp = control.list_agent_runtimes(maxResults=5)
    assert "agentRuntimes" in ok_resp, f"expected agentRuntimes in response, got {ok_resp!r}"


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises; AssertionError if it succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

