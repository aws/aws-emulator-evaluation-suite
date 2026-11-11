"""search-image-sets-empty-datastore-returns-empty."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "search-image-sets-empty-datastore-returns-empty"
GROUP = "control-plane"
SERVICES = ["medical-imaging"]


def _create_datastore_retry(mi, ctx, timeout_s: float = 180.0) -> str:
    name = ctx.unique_name("sim2real-mi-ds-")
    token = ctx.unique_name("sim2real-mi-tok-")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return mi.create_datastore(
                datastoreName=name, clientToken=token, tags={"sim2real": "true"}
            )["datastoreId"]
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("ThrottlingException", "TooManyRequestsException") and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SearchImageSets against a freshly created, ACTIVE, empty datastore returns an empty
    list rather than an error."""
    mi = ctx.client("medical-imaging")
    datastore_id = _create_datastore_retry(mi, ctx)
    ctx.on_cleanup(lambda: mi.delete_datastore(datastoreId=datastore_id))

    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        if mi.get_datastore(datastoreId=datastore_id)["datastoreProperties"]["datastoreStatus"] == "ACTIVE":
            break
        time.sleep(3)

    resp = mi.search_image_sets(datastoreId=datastore_id)
    assert resp["imageSetsMetadataSummaries"] == [], resp["imageSetsMetadataSummaries"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
