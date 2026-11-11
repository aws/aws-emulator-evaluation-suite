"""create-environment-connector-environment-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-environment-connector-environment-not-found"
GROUP = "errors"
SERVICES = ["evs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEnvironmentConnector against a well-formed but nonexistent environmentId
    raises ResourceNotFoundException, and no connector is created anywhere."""
    evs = ctx.client("evs")
    code, message = _error(
        lambda: evs.create_environment_connector(
            environmentId="env-0000000000",
            type="VCENTER",
            applianceFqdn="vcenter.sim2real.invalid",
            secretIdentifier=ctx.unique_name("sim2real-evs-secret-"),
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a nonexistent environmentId, got {code!r}"
    )
    assert message == "Environment env-0000000000 was not found", f"unexpected message {message!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
