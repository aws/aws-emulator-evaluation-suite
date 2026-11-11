"""get-instance-nonexistent-not-found."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-instance-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["supplychain"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetInstance on a syntactically valid but never-created instanceId returns
    ResourceNotFoundException, while a just-created instance is fetched first as a positive
    control so a target rejecting every GetInstance cannot pass."""
    sc = ctx.client("supplychain", region="us-east-1")  # AWS Supply Chain is not available in us-west-2
    name = ctx.unique_name("sim2real-sc-")
    created = sc.create_instance(
        instanceName=name, instanceDescription="sim2real behavioral check", tags={"team": "sim2real"}
    )["instance"]
    instance_id = created["instanceId"]
    ctx.on_cleanup(lambda: _delete_with_retry(sc, instance_id))

    # positive control: GetInstance succeeds against the instance we just created
    fetched = sc.get_instance(instanceId=instance_id)["instance"]
    assert fetched["instanceId"] == instance_id, f"expected {instance_id}, got {fetched['instanceId']}"

    bogus_instance_id = str(uuid.uuid4())
    code, message = _error(lambda: sc.get_instance(instanceId=bogus_instance_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "Instance not found.", f"expected 'Instance not found.', got {message!r}"


# ===== helpers =====

def _error(fn):
    """Call fn(); return its ClientError code and message. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_with_retry(sc, instance_id, timeout_s=840.0, interval_s=2.0):
    """DeleteInstance is rejected with ConflictException while the instance is still
    Initializing: retry that to a deadline inside the cleanup budget; not-found is done."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sc.delete_instance(instanceId=instance_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code == "ConflictException" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
