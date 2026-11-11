"""op-contract-describeApplicationStatusCheckAssociations."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeApplicationStatusCheckAssociations"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeApplicationStatusCheckAssociations lists associations and rejects unknown filter names."""
    ec2 = ctx.client("ec2")
    _require_op(ec2, "describe_application_status_check_associations")

    # success path: account-wide association listing (no ApplicationStatusCheckIds filter)
    response = ec2.describe_application_status_check_associations()
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected 200, got {response['ResponseMetadata']['HTTPStatusCode']}"
    )
    # substantive assertion directly on the response body (confirmed shape: top-level
    # "Associations" list -- see the CLI Output section for
    # DescribeApplicationStatusCheckAssociations). Note: "Tags" is not a top-level
    # field on this response; per-item tags (if any) live under each association record.
    assert "Associations" in response, f"expected Associations in response body: {response!r}"
    associations = response["Associations"]
    assert isinstance(associations, list), f"expected Associations to be a list, got {associations!r}"
    for item in associations:
        assert isinstance(item, dict), f"association record should be dict-shaped, got {item!r}"
        # an association record identifies which check it belongs to and how it is targeted
        assert "ApplicationStatusCheckId" in item or "Key" in item, (
            f"association record missing ApplicationStatusCheckId/Key: {item!r}"
        )
    if not associations:
        # pagination contract: nextToken must be null/absent when there is nothing more to return
        assert response.get("NextToken") in (None, ""), (
            "NextToken should be empty/absent when the result set is empty"
        )

    # error boundary: an unrecognized filter name is rejected with InvalidFilter, the
    # code this API family uses for filter-name validation, distinct from a permission-check dry run.
    bogus_filter = "sim2real-not-a-real-filter"
    code, message = _error(
        lambda: ec2.describe_application_status_check_associations(
            Filters=[{"Name": bogus_filter, "Values": ["x"]}]
        )
    )
    assert code == "InvalidFilter", f"expected InvalidFilter, got {code!r}"
    expected = f"Invalid filter name: '{bogus_filter}'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _require_op(client: Any, op_name: str) -> None:

    if not hasattr(client, op_name):
        raise AssertionError(f"ec2 client missing operation {op_name!r} (botocore too old)")


def _error(fn):
    """Call fn(); return its error as (code, message). An unexpected SUCCESS raises rather than
    returning a falsy sentinel."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
