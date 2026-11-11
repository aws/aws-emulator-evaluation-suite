"""get-environment-nonexistent-id-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-environment-nonexistent-id-rejected"
GROUP = "error-semantics"
SERVICES = ["interconnect"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetEnvironment on an id that does not correspond to any Environment fails with InterconnectClientException."""
    ic = ctx.client("interconnect")
    bad_env_id = ctx.unique_name("sim2real-behav-no-env-")
    code, message = _error(lambda: ic.get_environment(id=bad_env_id))
    assert code == "InterconnectClientException", f"got {code!r}"
    expected = f"Unable to process request: This environment model with id {bad_env_id} could not be found"
    assert message == expected, f"got {message!r}"


def _error(fn):
    """Return (code, message) of the ClientError fn raises; an accepted call fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
