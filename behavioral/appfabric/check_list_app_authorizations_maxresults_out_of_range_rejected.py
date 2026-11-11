"""list-app-authorizations-maxresults-out-of-range-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "list-app-authorizations-maxresults-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["appfabric"]


def _error(fn):
    """Call fn(); return the refusal's (code, message). A success raises: a target that accepts
    what AWS refuses must fail here, not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")



def _af_client(ctx, service: str = "appfabric"):
    """A client pinned to us-east-1, an AppFabric region (ctx.region need not be one); every
    resource this check creates lives in that one region."""
    from botocore.config import Config

    return ctx.client(
        service, region="us-east-1", config=Config(retries={"max_attempts": 8, "mode": "standard"})
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListAppAuthorizations with maxResults=101, above the documented maximum of 100 that the SDK
    does not enforce, raises the service's ValidationException.
    """
    appfabric = _af_client(ctx)
    from botocore.exceptions import ClientError as _CE
    try:
        for b in appfabric.list_app_bundles(maxResults=100).get("appBundleSummaryList", []):
            try:
                appfabric.delete_app_bundle(appBundleIdentifier=b["arn"])
            except _CE:
                pass
    except _CE:
        pass

    bundle_arn = appfabric.create_app_bundle(clientToken=str(uuid.uuid4()))["appBundle"]["arn"]
    ctx.on_cleanup(lambda: appfabric.delete_app_bundle(appBundleIdentifier=bundle_arn))

    code, message = _error(
        lambda: appfabric.list_app_authorizations(appBundleIdentifier=bundle_arn, maxResults=101)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = (
        "1 validation error detected: Value at 'maxResults' failed to satisfy constraint: "
        "Member must have value less than or equal to 100"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


    # Positive control: the same call with an in-range maxResults succeeds.
    page = appfabric.list_app_authorizations(appBundleIdentifier=bundle_arn, maxResults=1)
    assert page["appAuthorizationSummaryList"] == [], (
        f"expected no app authorizations on a freshly created bundle, got "
        f"{page['appAuthorizationSummaryList']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
