"""invoke-rest-api-nonexistent-environment-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invoke-rest-api-nonexistent-environment-not-found"
GROUP = "error-semantics"
SERVICES = ["mwaa"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeRestApi against a Name that matches no environment raises ResourceNotFoundException."""
    mwaa = ctx.client("mwaa")
    name = ctx.unique_name("sim2real-mwaa-missing-")

    code, message = _error(lambda: mwaa.invoke_rest_api(Name=name, Path="/dags", Method="GET"))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == "Environment not found", f"got message {message!r}"


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
