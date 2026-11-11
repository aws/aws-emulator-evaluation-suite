"""get-workload-invalid-name-pattern-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-workload-invalid-name-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["launch-wizard"]


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetWorkload rejects a workloadName that does not start with a letter with ValidationException and its
    exact message, and ListWorkloads still returns workloads."""
    lw = ctx.client("launch-wizard")

    code, message = _error(lambda: lw.get_workload(workloadName="1InvalidLeadingDigit"))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == (
        "1 validation error detected: Value at 'workloadName' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [A-Za-z][a-zA-Z0-9-_]*"
    ), f"GetWorkload message: {message!r}"

    # positive control: a real, well-formed workload name still resolves successfully
    workloads = lw.list_workloads(maxResults=1)["workloads"]
    assert workloads, "expected at least one workload in the catalog"
    lw.get_workload(workloadName=workloads[0]["workloadName"])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
