"""list-organizations-features."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-organizations-features"
GROUP = 'organizations_features'
SERVICES = ['iam']

# Documented Organizations-membership precondition errors; both the modeled name (with the
# "Exception" suffix) and IAM's stripped wire form are accepted.
ORG_LIST_FEATURES_PRECONDITION_CODES = {
    "AccountNotManagementOrDelegatedAdministratorException",
    "AccountNotManagementOrDelegatedAdministrator",
    "OrganizationNotFoundException",
    "OrganizationNotFound",
    "OrganizationNotInAllFeaturesModeException",
    "OrganizationNotInAllFeaturesMode",
    "ServiceAccessNotEnabledException",
    "ServiceAccessNotEnabled",
    "AWSOrganizationsNotInUseException",
}


def _expected_denial(message, head):
    """``head`` plus the authorization-details pointer IAM appends, built from the per-request
    authorization id and console region that ``message`` carries; ``head`` alone when it has none."""
    found = re.search(
        r"\. Go to https://([a-z0-9-]+)\.console\.aws\.amazon\.com/iam/home\?region=\1"
        r"#/authorization-details/(\w+) for complete details, or call the GetRequestAuthorizationDetails "
        r"API with the following authorization id: \2$",
        message or "",
    )
    if found is None:
        return head
    region, auth_id = found.groups()
    return (
        f"{head}. Go to https://{region}.console.aws.amazon.com/iam/home?region={region}"
        f"#/authorization-details/{auth_id} for complete details, or call the "
        f"GetRequestAuthorizationDetails API with the following authorization id: {auth_id}"
    )


def _error_code(fn):
    """``(code, message)`` of a call real AWS refuses; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS refuses this call, but it succeeded and returned {result!r}")


def _unprivileged_client(ctx):
    """Return ``(user_name, iam client)`` for a new zero-permission user with a fresh access key.
    Polls STS until the key authenticates (new keys propagate eventually); cleanup is registered."""
    iam = ctx.client("iam")
    user_name = ctx.unique_name("nopriv-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])

    def _cleanup():
        try:
            for k in iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]:
                iam.delete_access_key(UserName=user_name, AccessKeyId=k["AccessKeyId"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_user(UserName=user_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    created = iam.create_access_key(UserName=user_name)["AccessKey"]
    creds = {
        "aws_access_key_id": created["AccessKeyId"],
        "aws_secret_access_key": created["SecretAccessKey"],
    }
    unpriv_sts = ctx.client("sts", creds=creds)
    # Bounded by the runner's remaining time, so a key that never authenticates fails here.
    budget_s = max(1.0, min(60.0, (ctx.time_left() or 60.0) - 5.0))
    deadline = time.monotonic() + budget_s
    while True:
        try:
            unpriv_sts.get_caller_identity()
            break
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("InvalidClientTokenId", "InvalidAccessKeyId"):
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"the new access key never authenticated within {budget_s:.0f}s; last {code}")
            time.sleep(3)
    return user_name, ctx.client("iam", creds=creds)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListOrganizationsFeatures either returns EnabledFeatures or fails with a documented
    Organizations precondition error; a zero-permission user is denied AccessDenied with AWS's
    exact message regardless of the account's Organizations state."""
    iam = ctx.client("iam")
    try:
        resp = iam.list_organizations_features()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        assert code in ORG_LIST_FEATURES_PRECONDITION_CODES, (
            f"expected a documented Organizations-membership precondition, got {code!r}"
        )
    else:
        assert "EnabledFeatures" in resp, f"missing EnabledFeatures: {resp}"

    unpriv_name, unpriv = _unprivileged_client(ctx)
    code2, message2 = _error_code(lambda: unpriv.list_organizations_features())
    assert code2 == "AccessDenied", f"expected AccessDenied for a zero-permission caller, got {code2}"
    expected_message = (
        f"User: arn:aws:iam::{ctx.account}:user/{unpriv_name} is not authorized to perform: "
        f"iam:ListOrganizationsFeatures on resource: * because no identity-based policy allows the "
        f"iam:ListOrganizationsFeatures action"
    )
    assert message2 == _expected_denial(message2, expected_message), (
        f"the zero-permission caller's denial must carry AWS's exact message {expected_message!r} "
        f"plus the authorization-details pointer; got {message2!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
