"""describe-workspace-malformed-id-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-workspace-malformed-id-rejected"
GROUP = "error-semantics"
SERVICES = ["grafana"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeWorkspace rejects a workspaceId that fails the ^g-[0-9a-f]{10}$ pattern with ValidationException."""
    grafana = ctx.client("grafana")
    # positive control: the API surface itself is healthy before we probe the rejection
    resp = grafana.list_workspaces()
    assert "workspaces" in resp, f"expected a workspaces key in ListWorkspaces response, got {resp!r}"
    code, message = _error(lambda: grafana.describe_workspace(workspaceId="not-a-valid-workspace-id"))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = "The workspaceId should satisfy the pattern ^g-[0-9a-f]{10}$."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its botocore (error code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
