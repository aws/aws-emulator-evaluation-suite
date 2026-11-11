"""tag-resource-list-untag-roundtrip."""
from __future__ import annotations

import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-list-untag-roundtrip"
GROUP = "control-plane"
SERVICES = ["medical-imaging"]


def _create_datastore_retry(mi, ctx, timeout_s: float = 600.0) -> str:
    name = ctx.unique_name("sim2real-mi-ds-")
    token = ctx.unique_name("sim2real-mi-tok-")
    deadline = time.monotonic() + timeout_s
    delay = 5.0
    while True:
        try:
            return mi.create_datastore(datastoreName=name, clientToken=token)["datastoreId"]
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("ThrottlingException", "TooManyRequestsException") and time.monotonic() < deadline:
                time.sleep(delay + random.random() * delay)
                delay = min(delay * 1.7, 60.0)
                continue
            raise


def _delete_datastore_retry(mi, datastore_id: str, timeout_s: float = 600.0):
    deadline = time.monotonic() + timeout_s
    delay = 5.0
    while True:
        try:
            return mi.delete_datastore(datastoreId=datastore_id)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("ThrottlingException", "TooManyRequestsException") and time.monotonic() < deadline:
                time.sleep(delay + random.random() * delay)
                delay = min(delay * 1.7, 60.0)
                continue
            raise



@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource attaches tags visible via ListTagsForResource, and UntagResource removes
    exactly the requested keys, leaving any other tag untouched."""
    mi = ctx.client("medical-imaging")
    datastore_id = _create_datastore_retry(mi, ctx)
    ctx.on_cleanup(lambda: _delete_datastore_retry(mi, datastore_id))

    got = mi.get_datastore(datastoreId=datastore_id)["datastoreProperties"]
    resource_arn = got["datastoreArn"]

    mi.tag_resource(resourceArn=resource_arn, tags={"env": "sim2real", "owner": "behavioral"})
    tags = mi.list_tags_for_resource(resourceArn=resource_arn)["tags"]
    assert tags == {"env": "sim2real", "owner": "behavioral"}, tags

    mi.untag_resource(resourceArn=resource_arn, tagKeys=["env"])
    tags_after = mi.list_tags_for_resource(resourceArn=resource_arn)["tags"]
    assert tags_after == {"owner": "behavioral"}, tags_after

    # Drain to ACTIVE so cleanup's DeleteDatastore does not race a still-CREATING datastore.
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        if mi.get_datastore(datastoreId=datastore_id)["datastoreProperties"]["datastoreStatus"] == "ACTIVE":
            break
        time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
