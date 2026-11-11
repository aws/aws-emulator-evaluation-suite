"""put-registry-scanning-configuration-org-policy-blocked."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-registry-scanning-configuration-org-policy-blocked"
GROUP = "server-side"
SERVICES = ["ecr"]

# Triggering BlockedByOrganizationPolicyException itself requires an AWS Organizations
# declarative/resource control policy (managed from the org management account) that
# restricts ecr:PutRegistryScanningConfiguration on this member account -- provisioning and
# tearing down an org-level policy is out of scope for a self-contained per-account check (it
# would mutate policy shared by sibling accounts in the org and needs management-account
# credentials the test runner does not hold). Closing that specific gap needs a dedicated
# org-policy fixture that (1) has management-account access to attach an RCP/declarative
# policy denying the action to the target account, (2) asserts the call fails with
# BlockedByOrganizationPolicyException while an unaffected sibling account's identical call
# still succeeds, and (3) detaches the policy afterward.
#
# What IS reachable and asserted below is the same underlying theme -- that
# PutRegistryScanningConfiguration is enforced server-side rather than being a blind
# store-whatever-you-send call: the API models "rules" with a hard maximum of 2 entries, so
# submitting a third rule must be rejected, must NOT partially apply, and a valid update must
# still go through and persist.


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ecr-registry-scanning")
def run(ctx) -> None:
    """PutRegistryScanningConfiguration rejects a configuration with more than the maximum
    of 2 rules, leaves the registry's existing scanning configuration untouched by the
    rejected call, and still accepts and persists a valid (<=2 rule) configuration."""
    ecr = ctx.client("ecr")
    original_config = ecr.get_registry_scanning_configuration()["scanningConfiguration"]
    ctx.on_cleanup(lambda: _restore_scanning_configuration(ecr, original_config))

    filter_root = ctx.unique_name("sim2real-ecr-scanrule-").lower().replace("_", "-")
    while filter_root and filter_root[-1] in "-_.":
        filter_root = filter_root[:-1]
    too_many_rules = [
        {
            "scanFrequency": "SCAN_ON_PUSH",
            "repositoryFilters": [{"filter": f"{filter_root}-{suffix}*", "filterType": "WILDCARD"}],
        }
        for suffix in ("a", "b", "c")
    ]

    code, message = _client_error(
        lambda: ecr.put_registry_scanning_configuration(scanType="BASIC", rules=too_many_rules)
    )
    assert code == "InvalidParameterException", (
        f"submitting {len(too_many_rules)} rules (model max is 2) should be rejected with "
        f"InvalidParameterException, got {code!r}"
    )
    expected_message = (
        "Invalid parameter at 'rules' failed to satisfy constraint: "
        "'Member must have length less than or equal to 2'"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the rejected call did not partially apply -- the configuration is
    # unchanged from what it was before the attempt
    unchanged = ecr.get_registry_scanning_configuration()["scanningConfiguration"]
    assert unchanged == original_config, (
        f"a rejected PutRegistryScanningConfiguration must not partially apply: "
        f"expected unchanged config {original_config!r}, got {unchanged!r}"
    )

    # positive control: a valid single-rule configuration is still accepted and persists --
    # this is not a blanket rejection of PutRegistryScanningConfiguration. (BASIC scanning
    # only supports the SCAN_ON_PUSH frequency, so a valid BASIC configuration has at most one
    # rule; multiple rules sharing the same frequency is itself rejected as invalid.)
    valid_rules = [too_many_rules[0]]
    put_resp = ecr.put_registry_scanning_configuration(scanType="BASIC", rules=valid_rules)
    assert put_resp["registryScanningConfiguration"]["rules"] == valid_rules, (
        f"a valid (<=2 rule) configuration must be accepted and echoed back: "
        f"expected {valid_rules!r}, got {put_resp['registryScanningConfiguration']['rules']!r}"
    )
    persisted = ecr.get_registry_scanning_configuration()["scanningConfiguration"]
    assert persisted["rules"] == valid_rules, (
        f"the valid configuration must persist across an independent read: "
        f"expected {valid_rules!r}, got {persisted['rules']!r}"
    )


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected success
    raises, so an emulator that accepts what AWS refuses fails loudly instead of reading as a
    code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _restore_scanning_configuration(ecr, config):
    ecr.put_registry_scanning_configuration(scanType=config["scanType"], rules=config.get("rules", []))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

