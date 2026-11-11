"""application-version-processing-reaches-failed-for-malformed-bundle."""
from __future__ import annotations

import io
import time
import zipfile

from behavioral_harness import tags

CHECK = "application-version-processing-reaches-failed-for-malformed-bundle"
GROUP = 'application-versions'
SERVICES = ['elasticbeanstalk']

# The API returns UPPERCASE statuses ("UNPROCESSED") while the Smithy enum spells them
# "Unprocessed"; comparisons normalise case for that reason only.
_TERMINAL = {"PROCESSED", "FAILED"}


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _zip_with(files):
    """A source bundle zip containing the given {name: body} files."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, body in files.items():
            zf.writestr(name, body)
    return buf.getvalue()


# Process=True validates env.yaml and .ebextensions YAML syntax only; an invalid
# Dockerrun.aws.json or an unknown option namespace still settles on PROCESSED.
_DOCKERRUN = '{"AWSEBDockerrunVersion": "1"}'
_GOOD_CONFIG = "option_settings:\n  aws:autoscaling:asg:\n    MinSize: '1'\n"
_BAD_CONFIG = "option_settings:\n  - : this is ][ not valid yaml\n\t\tbroken\n"


def _status(eb, app_name, label):
    """The (uppercased) ApplicationVersion Status for one label, or None if unlisted."""
    versions = eb.describe_application_versions(
        ApplicationName=app_name, VersionLabels=[label]
    )["ApplicationVersions"]
    return (versions[0].get("Status") or "").upper() if versions else None



@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """With Process=True a valid bundle settles on PROCESSED and one with invalid .ebextensions YAML
    on FAILED (still listed); with Process=False the same bad bundle stays UNPROCESSED.

    Reference: https://docs.aws.amazon.com/elasticbeanstalk/latest/api/API_CreateApplicationVersion.html
    """
    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")

    app_name = ctx.unique_name("sim2real-behav-eb-app-")
    eb.create_application(ApplicationName=app_name)
    ctx.on_cleanup(
        lambda _n=app_name: eb.delete_application(ApplicationName=_n, TerminateEnvByForce=True)
    )

    # Account-level managed bucket: never registered for cleanup (shared, and its bucket policy
    # blocks deletion). Only the objects written here are removed.
    bucket = eb.create_storage_location()["S3Bucket"]
    timeout_s = 600

    def _upload(label, payload):
        key = f"{app_name}/{label}.zip"
        s3.put_object(Bucket=bucket, Key=key, Body=payload)
        ctx.on_cleanup(lambda _k=key: s3.delete_object(Bucket=bucket, Key=_k))
        return key

    # --- Control leg: a well-formed .ebextensions config settles on PROCESSED. ---
    good_label = ctx.unique_name("sim2real-behav-v-good-")
    good_key = _upload(
        good_label,
        _zip_with({"Dockerrun.aws.json": _DOCKERRUN, ".ebextensions/opts.config": _GOOD_CONFIG}),
    )
    eb.create_application_version(
        ApplicationName=app_name,
        VersionLabel=good_label,
        SourceBundle={"S3Bucket": bucket, "S3Key": good_key},
        Process=True,
    )
    good_final = _poll_until(
        lambda: _status(eb, app_name, good_label),
        lambda s: s in _TERMINAL,
        timeout_s=timeout_s,
        interval_s=10,
        description=f"application version {good_label} reaching a terminal processing status",
    )
    assert good_final == "PROCESSED", (
        f"a well-formed source bundle submitted with Process=True must settle on PROCESSED, got "
        f"{good_final!r}"
    )

    # --- Negative leg: break exactly one thing — the .ebextensions config is not valid YAML. ---
    bad_label = ctx.unique_name("sim2real-behav-v-bad-")
    bad_key = _upload(
        bad_label,
        _zip_with({"Dockerrun.aws.json": _DOCKERRUN, ".ebextensions/opts.config": _BAD_CONFIG}),
    )
    bad_leg_start = time.monotonic()
    created = eb.create_application_version(
        ApplicationName=app_name,
        VersionLabel=bad_label,
        SourceBundle={"S3Bucket": bucket, "S3Key": bad_key},
        Process=True,
    )["ApplicationVersion"]
    initial = (created.get("Status") or "").upper()
    assert initial in ("PROCESSING", "BUILDING"), (
        f"a Process=True application version must be created in a non-terminal processing state "
        f"(PROCESSING or BUILDING); got {initial!r} -- a target that returns a terminal status "
        f"synchronously is not modelling the state machine"
    )
    bad_final = _poll_until(
        lambda: _status(eb, app_name, bad_label),
        lambda s: s in _TERMINAL,
        timeout_s=timeout_s,
        interval_s=10,
        description=f"application version {bad_label} reaching a terminal processing status",
    )
    bad_leg_elapsed_s = time.monotonic() - bad_leg_start
    assert bad_final == "FAILED", (
        f"a source bundle whose .ebextensions/*.config is not valid YAML must settle on FAILED, got "
        f"{bad_final!r}"
    )

    # --- Effect absent: the failed version is retained, not silently deleted or promoted. ---
    listed = eb.describe_application_versions(
        ApplicationName=app_name, VersionLabels=[bad_label]
    )["ApplicationVersions"]
    assert len(listed) == 1, (
        f"a version that failed processing must still be listed, got {listed!r}"
    )
    assert (listed[0]["Status"] or "").upper() == "FAILED", listed[0]
    assert listed[0]["SourceBundle"]["S3Key"] == bad_key, listed[0]

    # --- Process=False on the SAME malformed bundle must not invent a verdict. ---
    unproc_label = ctx.unique_name("sim2real-behav-v-unproc-")
    unproc_key = _upload(
        unproc_label,
        _zip_with({"Dockerrun.aws.json": _DOCKERRUN, ".ebextensions/opts.config": _BAD_CONFIG}),
    )
    unproc = eb.create_application_version(
        ApplicationName=app_name,
        VersionLabel=unproc_label,
        SourceBundle={"S3Bucket": bucket, "S3Key": unproc_key},
        Process=False,
    )["ApplicationVersion"]
    assert (unproc.get("Status") or "").upper() == "UNPROCESSED", (
        f"Process=False must leave the version UNPROCESSED even when the bundle is malformed — no "
        f"processing was requested, so no verdict may be reported; got {unproc.get('Status')!r}"
    )
    # The window is how long the same bundle took to reach FAILED with Process=True, so late
    # processing would be caught; repeated reads, not a single dwell-then-read.
    freeze_window_s = max(bad_leg_elapsed_s, 5.0)
    freeze_interval_s = max(freeze_window_s / 5, 1.0)
    freeze_deadline = time.monotonic() + freeze_window_s
    while time.monotonic() < freeze_deadline:
        time.sleep(freeze_interval_s)
        observed = _status(eb, app_name, unproc_label)
        assert observed == "UNPROCESSED", (
            f"an UNPROCESSED version must stay UNPROCESSED — a background job may have started "
            f"despite Process=False; got {observed!r} within a {freeze_window_s:.0f}s window "
            f"calibrated to this run's own bad-bundle processing time ({bad_leg_elapsed_s:.0f}s)"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
