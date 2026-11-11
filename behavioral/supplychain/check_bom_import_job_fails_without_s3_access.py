"""bom-import-job-fails-without-s3-access."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bom-import-job-fails-without-s3-access"
GROUP = "error-semantics"
SERVICES = ["supplychain"]

_DEPRECATED_MESSAGE = (
    "This API has been deprecated. Please contact ASC support team at "
    "https://aws.amazon.com/contact-us/ for more details."
)
# DeleteInstance refusals seen while a just-created instance is still settling.
_SETTLING_CODES = ("ConflictException", "ValidationException", "AccessDeniedException")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateBillOfMaterialsImportJob and GetBillOfMaterialsImportJob are withdrawn: both answer
    AccessDeniedException "This API has been deprecated..." even for a healthy Active instance
    (the positive control), so the asynchronous S3-access failure is never reached."""
    sc = _sc_client(ctx)
    instance_id = _create_active_instance(ctx, sc)

    code, message = _expect_denied(
        lambda: sc.create_bill_of_materials_import_job(
            instanceId=instance_id,
            s3uri="s3://sim2real-nonexistent-bucket/bom/import.csv",
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}: {message}"
    assert message == _DEPRECATED_MESSAGE, f"expected {_DEPRECATED_MESSAGE!r}, got {message!r}"

    code2, message2 = _expect_denied(
        lambda: sc.get_bill_of_materials_import_job(instanceId=instance_id, jobId=str(uuid.uuid4()))
    )
    assert code2 == "AccessDeniedException", f"expected AccessDeniedException, got {code2}: {message2}"
    assert message2 == _DEPRECATED_MESSAGE, f"expected {_DEPRECATED_MESSAGE!r}, got {message2!r}"


# ===== helpers =====

def _sc_client(ctx):
    """AWS Supply Chain is region-restricted: CreateInstance in us-west-2 answers
    `ValidationException: Amazon Connect Decisions is not supported in us-west-2.` The region is pinned through `ctx.client(..., region=)`."""
    return ctx.client("supplychain", region="us-east-1")


def _expect_denied(fn):
    try:
        fn()
    except ClientError as e:
        error = e.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError("expected the call to be denied, but it succeeded")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_active_instance(ctx, sc):
    name = ctx.unique_name("sim2real-sc-")
    instance = sc.create_instance(
        instanceName=name,
        instanceDescription="sim2real behavioral check",
        tags={"sim2real": CHECK},
    )["instance"]
    instance_id = instance["instanceId"]

    def _cleanup():
        # DeleteInstance can transiently answer 400/403 while the instance settles after
        # creation: retry those to a deadline, return on not-found, raise everything else.
        deadline = time.monotonic() + 45.0
        while True:
            try:
                sc.delete_instance(instanceId=instance_id)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code not in _SETTLING_CODES or time.monotonic() >= deadline:
                    raise
                time.sleep(2.0)

    ctx.on_cleanup(_cleanup)
    result = _poll_until(
        lambda: sc.get_instance(instanceId=instance_id)["instance"],
        lambda inst: inst["state"] in ("Active", "CreateFailed"),
        timeout_s=1200.0,
        interval_s=15.0,
    )
    if result["state"] != "Active":
        raise AssertionError(f"instance did not reach Active state: {result}")
    return instance_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
