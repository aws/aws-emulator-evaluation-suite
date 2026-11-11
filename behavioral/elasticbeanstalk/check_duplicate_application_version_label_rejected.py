"""duplicate-application-version-label-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "duplicate-application-version-label-rejected"
GROUP = "overly-permissive"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx: Any) -> None:
    """CreateApplicationVersion with an existing VersionLabel fails with InvalidParameterValue and the exact message,
    leaves the original version's Description and DateUpdated untouched, and a fresh label still creates."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-eb-app-")
    version_label = ctx.unique_name("sim2real-eb-ver-")

    eb.create_application(ApplicationName=app_name, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name))

    first = eb.create_application_version(
        ApplicationName=app_name,
        VersionLabel=version_label,
        Description="original",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["ApplicationVersion"]
    original_date_updated = first["DateUpdated"]

    code, message = _error_code(
        lambda: eb.create_application_version(
            ApplicationName=app_name, VersionLabel=version_label, Description="conflicting-second-attempt"
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    expected = f"Application Version {version_label} already exists."
    assert message == expected, f"expected {expected!r}, got {message!r}"

    unchanged = eb.describe_application_versions(ApplicationName=app_name, VersionLabels=[version_label])[
        "ApplicationVersions"
    ]
    assert len(unchanged) == 1, f"expected exactly one version {version_label!r}, found {len(unchanged)}"
    assert unchanged[0]["Description"] == "original", (
        f"rejected duplicate-label create mutated the existing version's description: {unchanged[0]['Description']!r}"
    )
    assert unchanged[0]["DateUpdated"] == original_date_updated, "rejected create touched DateUpdated"

    # positive control: a fresh, unused label on the same application still succeeds
    fresh_label = ctx.unique_name("sim2real-eb-ver2-")
    eb.create_application_version(
        ApplicationName=app_name,
        VersionLabel=fresh_label,
        Description="fresh",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    fresh = eb.describe_application_versions(ApplicationName=app_name, VersionLabels=[fresh_label])[
        "ApplicationVersions"
    ]
    assert len(fresh) == 1, f"expected exactly one version {fresh_label!r}, found {len(fresh)}"
    assert fresh[0]["Description"] == "fresh", (
        f"fresh-label create under a distinct label did not persist its description: {fresh[0]['Description']!r}"
    )


def _error_code(fn: Any) -> tuple[str, str]:
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    success raises, so an emulator accepting what AWS refuses fails loudly."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
