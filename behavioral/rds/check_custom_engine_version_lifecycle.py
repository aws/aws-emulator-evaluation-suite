"""custom-engine-version-lifecycle."""
from __future__ import annotations

import re

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "custom-engine-version-lifecycle"
GROUP = "state-machine"
SERVICES = ["rds"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCustomDBEngineVersion with Engine="custom-oracle-ee" is rejected with InvalidParameterValue
    ("Invalid DB engine") even with a fabricated KMS key and S3 bucket, so the engine check runs first,
    while DescribeDBEngineVersions for a standard engine succeeds."""
    rds = ctx.client("rds")

    # Positive control: RDS itself is reachable and healthy for this account/region.
    standard_versions = rds.describe_db_engine_versions(Engine="postgres", MaxRecords=20)["DBEngineVersions"]
    assert standard_versions, (
        "expected describe_db_engine_versions(Engine='postgres') to return at least one version -- "
        "otherwise the custom-engine rejection below would be indistinguishable from a broad RDS outage"
    )

    suffix = re.sub(r"[^a-z0-9_.-]", "", ctx.unique_name("sim2realbehavcev").lower())
    engine_version = f"19.{suffix}"
    bogus_bucket = ctx.unique_name("sim2real-behav-nonexistent-bucket-")
    bogus_key_arn = f"arn:aws:kms:{ctx.region}:000000000000:key/sim2real-nonexistent-key"

    def _create():
        rds.create_custom_db_engine_version(
            Engine="custom-oracle-ee",
            EngineVersion=engine_version,
            KMSKeyId=bogus_key_arn,
            DatabaseInstallationFilesS3BucketName=bogus_bucket,
            DatabaseInstallationFilesS3Prefix="media/",
        )

    error = _error(_create)
    assert error["Code"] == "InvalidParameterValue", (
        f"expected the custom-oracle-ee engine-availability gate to reject with InvalidParameterValue, "
        f"got {error['Code']!r}: {error.get('Message')!r}"
    )
    assert error.get("Message") == "Invalid DB engine", (
        f"expected the engine-specific rejection message (not a bucket/key complaint), "
        f"got {error.get('Message')!r}"
    )

    # Effect absent: confirm nothing with this identifier exists. A custom engine name only
    # becomes a recognized/describable "Engine" value once at least one CEV has ever been created
    # for it in this account -- since the create above was rejected before ever touching the
    # engine catalog, real AWS may reject the lookup itself ("Invalid DB engine") rather than
    # return an empty list. Either shape is equally conclusive proof no CEV exists.
    try:
        resp = rds.describe_db_engine_versions(Engine="custom-oracle-ee", EngineVersion=engine_version)
    except ClientError as e:
        assert e.response["Error"]["Code"] == "InvalidParameterValue", (
            f"unexpected error confirming no CEV was created: {e}"
        )
        assert e.response["Error"].get("Message") == "Unrecognized engine name: custom-oracle-ee", (
            f"unexpected message confirming no CEV was created: {e.response['Error'].get('Message')!r}"
        )
    else:
        assert resp["DBEngineVersions"] == [], "no CEV should have been created from the rejected request"


def _error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
