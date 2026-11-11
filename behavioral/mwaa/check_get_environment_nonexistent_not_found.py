"""get-environment-nonexistent-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-environment-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["mwaa"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetEnvironment on a well-formed but never-created Name raises ResourceNotFoundException."""
    mwaa = ctx.client("mwaa")
    name = ctx.unique_name("sim2real-mwaa-missing-")

    code, message = _error(lambda: mwaa.get_environment(Name=name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == f"Environment {name} not found.", f"got message {message!r}"

    # Positive control: the mwaa API itself is not just blanket-rejecting every call in
    # this account/region (an emulator that unconditionally errors would fail this too).
    control = mwaa.list_environments(MaxResults=5)
    assert "Environments" in control


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
