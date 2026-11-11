"""publish-profile-exceeds-version-quota-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "publish-profile-exceeds-version-quota-rejected"
GROUP = "overly-permissive"
SERVICES = ["healthlake"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A profile already holding the maximum 99 published versions rejects one more publish with ServiceQuotaExceededException."""
    healthlake = ctx.client("healthlake")
    name = ctx.unique_name("sim2real-profile-")

    created = healthlake.create_data_transformation_profile(
        SourceFormat="CCDA",
        ProfileName=name,
        Source={"ProfileMapping": {"ProfileMapping": {"Resources/Patient.vm": "content"}}},
        Tags={"sim2real-env": "test"},
    )
    profile_id = created["ProfileId"]
    ctx.on_cleanup(lambda: healthlake.delete_data_transformation_profile(ProfileId=profile_id))

    for i in range(99):
        _publish_with_retry(healthlake, profile_id, f"v{i + 1}")

    total = _poll_version_count(healthlake, profile_id, 99)
    assert total == 99, f"expected 99 published versions before hitting quota, found {total}"

    code, message = _error(
        lambda: healthlake.publish_data_transformation_profile(
            ProfileId=profile_id, SourceFormat="CCDA", ChangeDescription="v100-should-fail"
        )
    )
    assert code == "ServiceQuotaExceededException", f"expected quota rejection, got error code {code!r}"
    expected = "Maximum of 99 published versions exceeded"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absence: the rejected publish did not create a 100th published version.
    total_after = _count_published_versions(healthlake, profile_id)
    assert total_after == 99, f"expected the rejected publish to leave 99 versions, found {total_after}"


def _publish_with_retry(healthlake, profile_id, change_description, *, max_attempts=6):
    attempt = 0
    while True:
        try:
            healthlake.publish_data_transformation_profile(
                ProfileId=profile_id, SourceFormat="CCDA", ChangeDescription=change_description
            )
            return
        except ClientError as exc:
            attempt += 1
            if exc.response["Error"]["Code"] != "ThrottlingException" or attempt >= max_attempts:
                raise
            time.sleep(0.5 * attempt)


def _count_published_versions(healthlake, profile_id):
    # ListDataTransformationProfileVersions also returns the DRAFT (version 0);
    # only count published (Version >= 1) entries against the 99-version quota.
    total = 0
    next_token = None
    while True:
        kwargs = {"ProfileId": profile_id, "MaxResults": 100}
        if next_token:
            kwargs["NextToken"] = next_token
        page = healthlake.list_data_transformation_profile_versions(**kwargs)
        total += sum(1 for item in page["Items"] if item["Version"] >= 1)
        next_token = page.get("NextToken")
        if not next_token:
            return total


def _poll_version_count(healthlake, profile_id, expected_count, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_total = 0
    while time.monotonic() < deadline:
        last_total = _count_published_versions(healthlake, profile_id)
        if last_total == expected_count:
            return last_total
        time.sleep(interval_s)
    return last_total


def _error(fn):
    """Call fn(); return its ClientError (code, message). A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
