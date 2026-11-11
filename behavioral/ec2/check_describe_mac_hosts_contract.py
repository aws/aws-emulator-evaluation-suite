"""describe-mac-hosts-contract."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-mac-hosts-contract"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeMacHosts: success contract (list payload) and invalid-filter-name rejection."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_mac_hosts(MaxResults=5)
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected 200, got {resp['ResponseMetadata']['HTTPStatusCode']!r}"
    )
    mac_hosts = resp["MacHosts"]
    _assert_page_contract(mac_hosts, resp.get("NextToken"), max_results=5)

    # DescribeMacHosts only supports 'availability-zone' and 'instance-type' filters;
    # an unrecognized filter name must be rejected. The service surfaces this rejection
    # as InvalidRequest (not InvalidParameterValue) for this particular operation.
    code, message = _client_error(
        lambda: ec2.describe_mac_hosts(
            Filters=[{"Name": "sim2real-bogus-filter", "Values": ["x"]}]
        )
    )
    assert code == "InvalidRequest", f"expected InvalidRequest, got {code!r}"
    expected_message = "Invalid filter"
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"


def _assert_page_contract(items, next_token, *, max_results):
    # Substantive body/state assertion: the returned page must never exceed the
    # requested MaxResults, and per the documented contract NextToken is null once
    # fewer than MaxResults items come back (there is nothing left to paginate).
    assert isinstance(items, list), f"expected MacHosts to be a list, got {type(items)!r}"
    assert len(items) <= max_results, f"expected at most {max_results} items, got {len(items)}"
    if len(items) < max_results:
        assert not next_token, "NextToken must be empty when the returned page is not full"


def _client_error(fn):
    """Call fn() and return the (code, message) it is refused with; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
