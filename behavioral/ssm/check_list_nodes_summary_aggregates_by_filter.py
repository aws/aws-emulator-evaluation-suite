"""list-nodes-summary-aggregates-by-filter."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-nodes-summary-aggregates-by-filter"
GROUP = "error-semantics"
SERVICES = ["ssm"]


@tags("cap:c1", "concern:negative-classes", "plane:control", "axis:rejection")
def run(ctx) -> None:
    """ListNodes and ListNodesSummary each fail with UnsupportedOperationException and the exact message when the
    integrated node experience is not enabled, while DescribeInstanceInformation answers."""
    ssm = ctx.client("ssm")

    # Positive control: same credentials, same service, an operation that needs no
    # special enrollment. If this raises, the account/credentials are broken and the
    # refusals below would be indistinguishable from that.
    ssm.describe_instance_information(MaxResults=10)

    list_nodes_code, list_nodes_message = _expect_unsupported(
        lambda: ssm.list_nodes(MaxResults=50)
    )
    assert list_nodes_code == "UnsupportedOperationException", (
        f"ListNodes: expected UnsupportedOperationException, got {list_nodes_code!r}"
    )
    expected_list_nodes_message = "This is an unsupported operation for this account. You must first enable the Systems Manager integrated experience in your account."
    assert list_nodes_message == expected_list_nodes_message, (
        f"ListNodes: expected message {expected_list_nodes_message!r}, got {list_nodes_message!r}"
    )

    summary_code, summary_message = _expect_unsupported(
        lambda: ssm.list_nodes_summary(
            Aggregators=[
                {"AggregatorType": "Count", "TypeName": "Instance", "AttributeName": "Region"}
            ],
            MaxResults=50,
        )
    )
    assert summary_code == "UnsupportedOperationException", (
        f"ListNodesSummary: expected UnsupportedOperationException, got {summary_code!r}"
    )
    expected_summary_message = "This is an unsupported operation for this account. You must first enable the Systems Manager integrated experience in your account."
    assert summary_message == expected_summary_message, (
        f"ListNodesSummary: expected message {expected_summary_message!r}, got {summary_message!r}"
    )


def _expect_unsupported(call) -> tuple[str, str]:
    """Invoke `call`; raise on unexpected success, else return (code, message)."""
    try:
        resp = call()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected UnsupportedOperationException, call succeeded: {resp}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
