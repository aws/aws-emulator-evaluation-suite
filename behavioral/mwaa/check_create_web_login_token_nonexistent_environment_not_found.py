"""create-web-login-token-nonexistent-environment-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-web-login-token-nonexistent-environment-not-found"
GROUP = "error-semantics"
SERVICES = ["mwaa"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateWebLoginToken against a Name that matches no environment raises ResourceNotFoundException,
    and the mwaa API is not merely blanket-denying every call in this account/region."""
    mwaa = ctx.client("mwaa")
    name = ctx.unique_name("sim2real-mwaa-missing-")

    code, message = _error(lambda: mwaa.create_web_login_token(Name=name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, actual_code={code!r}"
    assert message == "Environment not found", f"actual_message={message!r}"

    # Positive control: the mwaa API itself is not just blanket-rejecting every call in
    # this account/region (an emulator that unconditionally errors would fail this too).
    control = mwaa.list_environments(MaxResults=5)
    assert "Environments" in control, f"expected an Environments key, actual={control!r}"


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
