"""upload-processing-accepts-arbitrary-data-but-rejects-invalid-app-package."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "upload-processing-accepts-arbitrary-data-but-rejects-invalid-app-package"
GROUP = 'upload-processing'
SERVICES = ['devicefarm']


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _put(ctx, url: str, body: bytes) -> None:
    import requests

    target, headers = ctx.endpoint_route(url)
    headers = {**headers, "Content-Type": "application/octet-stream"}
    r = requests.put(target, data=body, headers=headers, verify=ctx.http_verify, timeout=30)
    assert r.status_code == 200, f"upload PUT returned {r.status_code}: {r.text[:200]!r}"


def _wait_for_terminal(df, arn: str, *, budget_s: float = 120.0, poll_s: float = 3.0) -> dict:
    deadline = time.monotonic() + budget_s
    upload = df.get_upload(arn=arn)["upload"]
    while upload["status"] not in ("SUCCEEDED", "FAILED"):
        if time.monotonic() > deadline:
            raise AssertionError(f"upload {arn} never reached a terminal status; last={upload!r}")
        time.sleep(poll_s)
        upload = df.get_upload(arn=arn)["upload"]
    return upload


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane",
      "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Device Farm parses an uploaded app package: arbitrary bytes succeed as EXTERNAL_DATA,
    but the same bytes rejected as ANDROID_APP fail processing with a specific error code.
    """
    df = ctx.client("devicefarm")
    project_name = ctx.unique_name("sim2real-behav-df-upload-project-")
    project_arn = df.create_project(name=project_name)["project"]["arn"]
    ctx.on_cleanup(_teardown(lambda: df.delete_project(arn=project_arn), "NotFoundException"))

    # Positive control: EXTERNAL_DATA accepts arbitrary bytes and reaches SUCCEEDED.
    good_name = ctx.unique_name("sim2real-behav-df-good-") + ".dat"
    good = df.create_upload(projectArn=project_arn, name=good_name, type="EXTERNAL_DATA")["upload"]
    ctx.on_cleanup(_teardown(lambda: df.delete_upload(arn=good["arn"]), "NotFoundException"))
    _put(ctx, good["url"], b"sim2real arbitrary payload, any bytes are valid EXTERNAL_DATA")
    good_final = _wait_for_terminal(df, good["arn"])
    assert good_final["status"] == "SUCCEEDED", (
        f"EXTERNAL_DATA upload of arbitrary bytes ended {good_final['status']!r}, "
        f"expected SUCCEEDED (metadata={good_final.get('metadata')!r})"
    )

    # Negative: ANDROID_APP requires a real app package; a syntactically-valid zip that is not
    # one fails processing instead of being accepted as an opaque blob.
    bad_name = ctx.unique_name("sim2real-behav-df-bad-") + ".apk"
    bad = df.create_upload(projectArn=project_arn, name=bad_name, type="ANDROID_APP")["upload"]
    ctx.on_cleanup(_teardown(lambda: df.delete_upload(arn=bad["arn"]), "NotFoundException"))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml", b"not a real manifest")
    _put(ctx, bad["url"], buf.getvalue())
    bad_final = _wait_for_terminal(df, bad["arn"])
    assert bad_final["status"] == "FAILED", (
        f"ANDROID_APP upload of a non-APK zip ended {bad_final['status']!r}, expected FAILED"
    )
    failure = json.loads(bad_final["metadata"])
    assert failure["errorCode"] == "ANDROID_APP_AAPT_DEBUG_BADGING_FAILED", (
        f"expected errorCode ANDROID_APP_AAPT_DEBUG_BADGING_FAILED, got {failure!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
