"""describe-workspace-nonexistent-id-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-workspace-nonexistent-id-not-found"
GROUP = "error-semantics"
SERVICES = ["grafana"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeWorkspace on a well-formed but unassigned workspaceId returns ResourceNotFoundException."""
    grafana = ctx.client("grafana")
    # syntactically valid per ^g-[0-9a-f]{10}$ but never issued by CreateWorkspace
    code, message = _error(lambda: grafana.describe_workspace(workspaceId="g-0000000000"))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = f"Workspace with id=g-0000000000 of account={ctx.account} does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    # positive control: the API surface itself is healthy
    resp = grafana.list_versions()
    assert "grafanaVersions" in resp, f"expected 'grafanaVersions' key, got {resp!r}"


def _error(fn):
    """Call fn(); return its botocore (error code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects describe_workspace for a never-issued id, but it SUCCEEDED and "
        f"returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
