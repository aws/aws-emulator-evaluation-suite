"""create-application-version-duplicate-label-must-fail."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-application-version-duplicate-label-must-fail"
GROUP = 'overly-permissive'
SERVICES = ['elasticbeanstalk']

def _err(fn):
    """Call fn(); return the botocore (Code, Message). An unexpected success raises, so an
    emulator accepting a call real AWS refuses is not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateApplicationVersion with the same VersionLabel must be rejected, must not
    mutate the existing version, and a fresh unused label on the same application must still
    succeed (positive control)."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-behav-eb-app-")
    eb.create_application(
        ApplicationName=app_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda _n=app_name: eb.delete_application(ApplicationName=_n, TerminateEnvByForce=True))

    label = ctx.unique_name("sim2real-behav-v-")
    original = eb.create_application_version(
        ApplicationName=app_name, VersionLabel=label, Description="original"
    )["ApplicationVersion"]

    code, message = _err(
        lambda: eb.create_application_version(
            ApplicationName=app_name, VersionLabel=label, Description="dupe"
        )
    )
    assert code == "InvalidParameterValue", (
        f"re-creating an existing application version must fail with InvalidParameterValue, "
        f"got {code!r}"
    )
    expected = f"Application Version {label} already exists."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    versions = eb.describe_application_versions(ApplicationName=app_name, VersionLabels=[label])[
        "ApplicationVersions"
    ]
    assert len(versions) == 1, (
        f"a rejected duplicate must not create a second application version, found {len(versions)}"
    )
    assert versions[0]["Description"] == "original", (
        f"rejected duplicate-label create mutated the existing version's description: "
        f"{versions[0]['Description']!r}"
    )
    assert versions[0]["DateUpdated"] == original["DateUpdated"], (
        "rejected duplicate-label create touched the existing version's DateUpdated"
    )

    # positive control: a fresh, unused label on the same application still succeeds
    fresh_label = ctx.unique_name("sim2real-behav-v2-")
    eb.create_application_version(ApplicationName=app_name, VersionLabel=fresh_label, Description="fresh")
    fresh = eb.describe_application_versions(ApplicationName=app_name, VersionLabels=[fresh_label])[
        "ApplicationVersions"
    ]
    assert len(fresh) == 1 and fresh[0]["Description"] == "fresh", (
        f"expected the fresh-label create to succeed and be visible, got {fresh!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
