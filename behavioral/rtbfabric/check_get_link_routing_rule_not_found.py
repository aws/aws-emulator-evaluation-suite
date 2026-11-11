"""get-link-routing-rule-not-found."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "get-link-routing-rule-not-found"
GROUP = "error-semantics"
SERVICES = ["rtbfabric"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetLinkRoutingRule on a well-formed but nonexistent gateway, link and rule triple (plain hex
    id suffixes, which pass format validation) is refused with ResourceNotFoundException ("The
    requested resource was not found.").
    """
    rtb = ctx.client("rtbfabric")
    fake_gateway_id = "rtb-gw-" + uuid.uuid4().hex[:18]
    fake_link_id = "link-" + uuid.uuid4().hex[:18]
    fake_rule_id = "rule-" + uuid.uuid4().hex[:18]

    error = _client_error(
        lambda: rtb.get_link_routing_rule(
            gatewayId=fake_gateway_id, linkId=fake_link_id, ruleId=fake_rule_id
        )
    )
    assert error["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {error['Code']}"
    expected_message = "The requested resource was not found."
    assert error["Message"] == expected_message, f"expected {expected_message!r}, got {error['Message']!r}"


def _client_error(fn):
    """Call fn(); return its botocore error (Code and Message). An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must fail loudly, not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
