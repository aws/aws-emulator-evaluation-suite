"""concurrent-publish-profile-versions-sequential."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-publish-profile-versions-sequential"
GROUP = "concurrency"
SERVICES = ["healthlake"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent PublishDataTransformationProfile calls on the same profile allocate unique, contiguous version numbers (no duplicates, no gaps)."""
    healthlake = ctx.client("healthlake")
    name = ctx.unique_name("sim2real-profile-")

    created = healthlake.create_data_transformation_profile(
        SourceFormat="CCDA",
        ProfileName=name,
        Source={"ProfileMapping": {"ProfileMapping": {"Resources/Patient.vm": "content"}}},
        Tags={"sim2real": CHECK},
    )
    profile_id = created["ProfileId"]
    ctx.on_cleanup(lambda: healthlake.delete_data_transformation_profile(ProfileId=profile_id))

    racer_count = 8

    def _publish_with_retry(i):
        attempt = 0
        while True:
            try:
                resp = healthlake.publish_data_transformation_profile(
                    ProfileId=profile_id, SourceFormat="CCDA", ChangeDescription=f"racer-{i}"
                )
                return resp["Version"]
            except ClientError as exc:
                attempt += 1
                if exc.response["Error"]["Code"] != "ThrottlingException" or attempt >= 6:
                    raise
                time.sleep(0.3 * attempt)

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        versions = list(pool.map(_publish_with_retry, range(racer_count)))

    assert len(versions) == racer_count, f"expected {racer_count} publish responses, got {versions}"
    assert len(set(versions)) == racer_count, f"duplicate version numbers under contention: {versions}"
    assert sorted(versions) == list(range(1, racer_count + 1)), (
        f"expected a contiguous 1..{racer_count} version sequence, got {sorted(versions)}"
    )

    # the profile's published-version list agrees with what each racer was told it got.
    # (list includes the DRAFT as version 0, and may lag the publish acks slightly;
    # poll to a bounded stable state and only compare the published (>=1) entries)
    listed_versions = _poll_version_list(healthlake, profile_id, racer_count)
    assert listed_versions == list(range(1, racer_count + 1)), (
        f"expected the listed published versions to be {list(range(1, racer_count + 1))}, "
        f"got {listed_versions}"
    )


def _poll_version_list(healthlake, profile_id, expected_count, *, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last_versions = []
    while time.monotonic() < deadline:
        listed = healthlake.list_data_transformation_profile_versions(ProfileId=profile_id)
        last_versions = sorted(item["Version"] for item in listed["Items"] if item["Version"] >= 1)
        if len(last_versions) == expected_count:
            return last_versions
        time.sleep(interval_s)
    raise AssertionError(
        f"listed published versions never reached {expected_count} within {timeout_s}s: "
        f"last saw {last_versions}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
