"""op-contract-list-organizations-features."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-list-organizations-features"
GROUP = "error-semantics"
SERVICES = ["iam"]

_ORG_BOUNDARY_CODES = {
    "OrganizationNotFoundException",
    "AccountNotManagementOrDelegatedAdministratorException",
    "ServiceAccessNotEnabledException",
    "OrganizationNotInAllFeaturesModeException",
}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListOrganizationsFeatures: either the success-path shape (account is an org
    management/delegated-admin account with trusted access enabled) or the org-membership
    error boundary (the overwhelmingly common case for a standalone test account)."""
    iam = ctx.client("iam")

    try:
        resp = iam.list_organizations_features()
    except ClientError as e:
        code = e.response["Error"]["Code"]
        status = e.response["ResponseMetadata"]["HTTPStatusCode"]
        assert code in _ORG_BOUNDARY_CODES, f"unexpected error code: {code}"
        assert status in (400, 403, 404), f"expected 400/403/404 for {code}, got {status}"
        # The message of each boundary code AWS has answered with; the others are unpinned.
        expected_messages = {
            "ServiceAccessNotEnabledException": (
                f"Trusted Access for IAM not enabled by organization of input account {ctx.account}."
            ),
        }
        message = e.response["Error"].get("Message")
        if code in expected_messages:
            assert message == expected_messages[code], f"{code}: {message!r}"
    else:
        features = resp.get("EnabledFeatures")
        assert isinstance(features, list), f"expected EnabledFeatures list, got {features!r}"
        org_id = resp.get("OrganizationId")
        assert isinstance(org_id, str) and org_id, f"expected non-empty OrganizationId, got {org_id!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
