"""list-app-bundles-reflects-created."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "list-app-bundles-reflects-created"
GROUP = "lifecycle"
SERVICES = ["appfabric"]


def _af_client(ctx, service: str = "appfabric"):
    """A client pinned to us-east-1, an AppFabric region (ctx.region need not be one); every
    resource this check creates lives in that one region."""
    from botocore.config import Config

    return ctx.client(
        service, region="us-east-1", config=Config(retries={"max_attempts": 8, "mode": "standard"})
    )


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly created app bundle appears in ListAppBundles, walking pagination if needed."""
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

    seen_arns: set[str] = set()
    next_token = None
    for _ in range(50):  # bounded pagination walk, never an unbounded loop
        kwargs = {"maxResults": 100}
        if next_token:
            kwargs["nextToken"] = next_token
        page = appfabric.list_app_bundles(**kwargs)
        seen_arns.update(item["arn"] for item in page.get("appBundleSummaryList", []))
        next_token = page.get("nextToken")
        if not next_token or bundle_arn in seen_arns:
            break

    assert bundle_arn in seen_arns, (
        f"created app bundle {bundle_arn} did not appear in ListAppBundles "
        f"(walked {len(seen_arns)} arns: {sorted(seen_arns)})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
