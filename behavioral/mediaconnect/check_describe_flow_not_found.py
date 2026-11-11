"""describe-flow-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-flow-not-found"
GROUP = "error-semantics"
SERVICES = ["mediaconnect"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeFlow on a syntactically valid but nonexistent FlowArn raises
    NotFoundException, and a DescribeFlow on a real flow (in the same file)
    still succeeds -- confirming rejection is targeted, not blanket."""
    mc = ctx.client("mediaconnect")
    flow_arn = mc.create_flow(
        Name=ctx.unique_name("sim2real-mc-flow-"),
        Source={"Name": "source1", "Protocol": "rtp", "WhitelistCidr": "203.0.113.0/24"},
        FlowTags={"sim2real": CHECK},
    )["Flow"]["FlowArn"]
    ctx.on_cleanup(lambda: mc.delete_flow(FlowArn=flow_arn))

    bogus_arn = flow_arn[:-6] + "ffffff"
    code, message = _client_error(lambda: mc.describe_flow(FlowArn=bogus_arn))
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}"
    expected = f"Not found: {bogus_arn}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # positive control: the real flow still describes fine
    described = mc.describe_flow(FlowArn=flow_arn)["Flow"]
    assert described["FlowArn"] == flow_arn, (
        f"expected FlowArn {flow_arn!r}, got {described['FlowArn']!r}"
    )


def _client_error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except Exception as exc:
        err = getattr(exc, "response", {}).get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected NotFoundException, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
