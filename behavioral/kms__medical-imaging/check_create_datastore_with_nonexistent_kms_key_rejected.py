"""create-datastore-with-nonexistent-kms-key-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-datastore-with-nonexistent-kms-key-rejected"
GROUP = "sse_kms"
SERVICES = ["kms", "medical-imaging"]

_BAD_KEY = ("ValidationException", "The provided KMS key for datastore cannot be located.")


def _wait_terminal(mi, datastore_id, deadline_s=120):
    deadline = time.monotonic() + deadline_s
    while True:
        props = mi.get_datastore(datastoreId=datastore_id)["datastoreProperties"]
        if props["datastoreStatus"] != "CREATING":
            return props
        if time.monotonic() > deadline:
            raise AssertionError(f"datastore did not leave CREATING, last={props!r}")
        time.sleep(3)


def _names(mi, name):
    for page in mi.get_paginator("list_datastores").paginate():
        for d in page["datastoreSummaries"]:
            if d["datastoreName"] == name:
                yield d


def _call_past_throttle(fn, deadline_s=60.0):
    """``fn()``'s outcome, retrying only while the account itself is being throttled."""
    deadline = time.monotonic() + deadline_s
    delay = 1.0
    while True:
        try:
            return ("ok", fn())
        except ClientError as exc:
            code = exc.response["Error"].get("Code") or ""
            if "Throttl" not in code and "TooManyRequests" not in code:
                return ("error", exc)
            if time.monotonic() > deadline:
                return ("error", exc)
            time.sleep(delay)
            delay = min(delay * 2, 10.0)


def _delete_datastore(mi, datastore_id):
    """DeleteDatastore, retrying only an account-rate throttle; any other failure raises."""
    outcome, result = _call_past_throttle(lambda: mi.delete_datastore(datastoreId=datastore_id))
    if outcome == "error":
        raise result


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """CreateDatastore's kmsKeyArn is checked against KMS: a well-formed but nonexistent key ARN
    is refused and no data store is created, while the identical call with no kmsKeyArn succeeds.
    """
    kms = ctx.client("kms")
    mi = ctx.client("medical-imaging")

    good_name = ctx.unique_name("sim2real-xsvc-mi-ds-ctl-")
    outcome, good = _call_past_throttle(lambda: mi.create_datastore(
        datastoreName=good_name,
        clientToken=ctx.unique_name("sim2real-xsvc-mi-tok-"),
        tags={"sim2real": "xsvc-kms-medical-imaging"},
    ))
    assert outcome == "ok", f"CreateDatastore for the control data store failed: {good!r}"
    good_id = good["datastoreId"]
    ctx.on_cleanup(lambda: _delete_datastore(mi, good_id))
    assert good["datastoreStatus"] == "CREATING", (
        f"CreateDatastore must return CREATING synchronously, got {good['datastoreStatus']!r}"
    )
    active = _wait_terminal(mi, good_id)
    assert active["datastoreStatus"] == "ACTIVE", (
        f"the control data store did not reach ACTIVE: {active!r}"
    )

    missing_arn = f"arn:aws:kms:{ctx.region}:{ctx.account}:key/{uuid.uuid4()}"
    try:
        kms.describe_key(KeyId=missing_arn)
    except ClientError as exc:
        assert exc.response["Error"].get("Code") == "NotFoundException", (
            f"the fabricated key must not exist, got {exc.response['Error']!r}"
        )
    else:
        raise AssertionError(f"the fabricated key {missing_arn!r} unexpectedly exists")

    bad_name = ctx.unique_name("sim2real-xsvc-mi-ds-bad-")

    def _create_bad():
        return mi.create_datastore(
            datastoreName=bad_name,
            clientToken=ctx.unique_name("sim2real-xsvc-mi-tok-"),
            kmsKeyArn=missing_arn,
            tags={"sim2real": "xsvc-kms-medical-imaging"},
        )

    outcome, result = _call_past_throttle(_create_bad)
    if outcome == "ok":
        ctx.on_cleanup(lambda: _delete_datastore(mi, result["datastoreId"]))
        raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")
    err = result.response["Error"]
    got = (err.get("Code"), err.get("Message"))

    assert got == _BAD_KEY, (
        f"CreateDatastore naming a well-formed but nonexistent KMS key must fail with "
        f"{_BAD_KEY!r}, got {got!r}"
    )

    leftover = list(_names(mi, bad_name))
    assert leftover == [], (
        f"a refused CreateDatastore naming a nonexistent key must leave no data store behind: "
        f"{leftover!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
