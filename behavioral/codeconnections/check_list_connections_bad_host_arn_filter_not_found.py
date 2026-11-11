"""list-connections-bad-host-arn-filter-not-found."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "list-connections-bad-host-arn-filter-not-found"
GROUP = "error-semantics"
SERVICES = ["codeconnections"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListConnections with a HostArnFilter that does not reference an existing host
    raises ResourceNotFoundException; an unfiltered ListConnections still succeeds."""
    cc = ctx.client("codeconnections")
    bogus_host_arn = (
        f"arn:aws:codeconnections:{ctx.region}:{ctx.account}:host/{uuid.uuid4()}"
    )

    code, message = _error(
        lambda: cc.list_connections(HostArnFilter=bogus_host_arn)
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a HostArnFilter naming a host that "
        f"was never created, got {code!r}"
    )
    assert message == f"No host exists with the ARN: {bogus_host_arn}", f"message: {message!r}"

    # positive control: an unfiltered list call still works normally
    resp = cc.list_connections()
    assert "Connections" in resp, f"expected a Connections key in {resp!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected ListConnections to reject the bogus HostArnFilter, but it "
        f"SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
