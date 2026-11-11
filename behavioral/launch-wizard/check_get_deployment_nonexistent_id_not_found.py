"""get-deployment-nonexistent-id-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-deployment-nonexistent-id-not-found"
GROUP = "error-semantics"
SERVICES = ["launch-wizard"]


def _client_error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected success raises, so
    a target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetDeployment for a well-formed (passes length/pattern constraints) but nonexistent
    deploymentId raises ResourceNotFoundException, while ListDeployments still succeeds."""
    lw = ctx.client("launch-wizard")
    bogus_id = "sim2real0000000000nosuch"

    code, message = _client_error(lambda: lw.get_deployment(deploymentId=bogus_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == "The specified deployment does not exist.", f"got message={message!r}"

    # effect absent: the bogus id genuinely does not correspond to any real deployment,
    # while the channel and a real lookup still work
    listed = lw.list_deployments(maxResults=100)["deployments"]
    assert all(d.get("id") != bogus_id for d in listed), (
        "bogus deployment id unexpectedly present in ListDeployments"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
