"""recording-configurations-list-reflects-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "recording-configurations-list-reflects-lifecycle"
GROUP = "state"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListRecordingConfigurations includes a newly created configuration and stops
    including it once it has been deleted."""
    ivs = ctx.client("ivs")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-ivs-listrec-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))

    cfg_arn = ivs.create_recording_configuration(
        name=ctx.unique_name("sim2real-ivs-listrec-cfg-"),
        destinationConfiguration={"s3": {"bucketName": bucket}},
        tags={"purpose": "sim2real"},
    )["recordingConfiguration"]["arn"]

    deleted = {"done": False}

    def _cleanup_cfg():
        if not deleted["done"]:
            ivs.delete_recording_configuration(arn=cfg_arn)

    ctx.on_cleanup(_cleanup_cfg)

    # give the configuration a moment to leave CREATING so it is a stable list member
    _poll_until(
        lambda: ivs.get_recording_configuration(arn=cfg_arn)["recordingConfiguration"][
            "state"
        ],
        lambda s: s in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=90,
        interval_s=3,
    )

    present = _all_recording_configurations(ivs)
    assert any(c["arn"] == cfg_arn for c in present), (
        f"expected {cfg_arn} in ListRecordingConfigurations, got arns={[c['arn'] for c in present]}"
    )

    ivs.delete_recording_configuration(arn=cfg_arn)
    deleted["done"] = True

    absent = _all_recording_configurations(ivs)
    assert not any(c["arn"] == cfg_arn for c in absent), (
        f"expected {cfg_arn} gone from ListRecordingConfigurations, still present in "
        f"arns={[c['arn'] for c in absent]}"
    )

    get_error = _error(lambda: ivs.get_recording_configuration(arn=cfg_arn))
    assert get_error["Code"] == "ResourceNotFoundException", (
        f"expected GetRecordingConfiguration on a deleted arn to raise "
        f"ResourceNotFoundException, got {get_error['Code']!r}"
    )
    assert get_error["Message"] == f"Resource: {cfg_arn} not found", repr(get_error["Message"])

    delete_again = _error(lambda: ivs.delete_recording_configuration(arn=cfg_arn))
    assert delete_again["Code"] == "ResourceNotFoundException", (
        f"expected a second DeleteRecordingConfiguration on a dead arn to also fail with "
        f"ResourceNotFoundException, got {delete_again['Code']!r}"
    )
    assert delete_again["Message"] == f"Resource: {cfg_arn} not found", repr(delete_again["Message"])


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


def _all_recording_configurations(ivs):
    out = []
    token = None
    while True:
        kwargs = {"maxResults": 100}
        if token:
            kwargs["nextToken"] = token
        resp = ivs.list_recording_configurations(**kwargs)
        out.extend(resp["recordingConfigurations"])
        token = resp.get("nextToken")
        if not token:
            return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
