"""delete-default-sampling-rule-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-default-sampling-rule-fails"
GROUP = 'overly-permissive'
SERVICES = ['xray']


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _delete_rule_if_present(xr, name):
    """Teardown: the check deletes its control rule itself, so a second delete finding it gone
    is the expected outcome, not a failure."""
    try:
        xr.delete_sampling_rule(RuleName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Message") != "Sampling rule does not exist":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """The reserved 'Default' sampling rule cannot be deleted (protected-resource boundary)."""
    xr = ctx.client("xray")
    listed = [r["SamplingRule"]["RuleName"] for r in xr.get_sampling_rules()["SamplingRuleRecords"]]
    assert "Default" in listed, "expected the built-in Default sampling rule to exist"

    # Positive control: prove delete_sampling_rule works at all on this account/target,
    # so the Default-specific rejection below is not indistinguishable from "every delete fails".
    control_name = ctx.unique_name("sim2real-behav-r-")
    xr.create_sampling_rule(SamplingRule={
        "RuleName": control_name,
        "ResourceARN": "*",
        "Priority": 9999,
        "FixedRate": 0.05,
        "ReservoirSize": 1,
        "ServiceName": "*",
        "ServiceType": "*",
        "Host": "*",
        "HTTPMethod": "*",
        "URLPath": "*",
        "Version": 1,
    })
    ctx.on_cleanup(lambda: _delete_rule_if_present(xr, control_name))
    xr.delete_sampling_rule(RuleName=control_name)
    listed_after_control = [
        r["SamplingRule"]["RuleName"] for r in xr.get_sampling_rules()["SamplingRuleRecords"]
    ]
    assert control_name not in listed_after_control, "positive control: ordinary rule delete did not take effect"

    error = _client_error(lambda: xr.delete_sampling_rule(RuleName="Default"))
    assert (error.get("Code"), error.get("Message")) == (
        "InvalidRequestException", "Cannot delete default sampling rule"
    ), f"expected InvalidRequestException 'Cannot delete default sampling rule', got {error!r}"

    listed_after = [r["SamplingRule"]["RuleName"] for r in xr.get_sampling_rules()["SamplingRuleRecords"]]
    assert "Default" in listed_after, "Default rule was removed despite failed delete"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
