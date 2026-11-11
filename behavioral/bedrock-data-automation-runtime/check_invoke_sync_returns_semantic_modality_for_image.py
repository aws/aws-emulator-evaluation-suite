"""invoke-sync-returns-semantic-modality-for-image."""
from __future__ import annotations

import base64
import struct
import zlib

from behavioral_harness import tags

CHECK = "invoke-sync-returns-semantic-modality-for-image"
GROUP = "data-plane"
SERVICES = ["bedrock-data-automation-runtime"]

# Region literals: the documented BDA cross-region-inference profile suffix per
# source region (arn:aws:bedrock:<region>:<account>:data-automation-profile/<suffix>).
# These are AWS's own fixed, region-pinned identifiers, not an account-varying quota.
_PROFILE_SUFFIX_BY_REGION = {
    "us-east-1": "us.data-automation-v1",
    "us-west-2": "us.data-automation-v1",
    "us-east-2": "us.data-automation-v1",
    "ca-central-1": "na.data-automation-v1",
    "eu-central-1": "eu.data-automation-v1",
    "eu-west-1": "eu.data-automation-v1",
    "eu-west-2": "eu.data-automation-v1",
    "eu-south-2": "eu.data-automation-v1",
    "ap-south-1": "apac.data-automation-v1",
    "ap-southeast-2": "apac.data-automation-v1",
    "ap-northeast-1": "apac.data-automation-v1",
    "us-gov-west-1": "us-gov.data-automation-v1",
}


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeDataAutomation on inline bytes reports semanticModality IMAGE for a PNG and
    DOCUMENT for a PDF through the same project and profile: the modality follows the payload.
    """
    bda = ctx.client("bedrock-data-automation-runtime")
    profile_arn = _profile_arn(ctx)
    project_arn = _create_project(ctx)

    image_response = bda.invoke_data_automation(
        inputConfiguration={"bytes": _minimal_png_bytes()},
        dataAutomationProfileArn=profile_arn,
        dataAutomationConfiguration={"dataAutomationProjectArn": project_arn},
    )
    assert image_response["semanticModality"] == "IMAGE", (
        f"expected semanticModality IMAGE for a PNG payload, got "
        f"{image_response['semanticModality']!r}"
    )

    document_response = bda.invoke_data_automation(
        inputConfiguration={"bytes": _minimal_pdf_bytes()},
        dataAutomationProfileArn=profile_arn,
        dataAutomationConfiguration={"dataAutomationProjectArn": project_arn},
    )
    assert document_response["semanticModality"] == "DOCUMENT", (
        f"expected semanticModality DOCUMENT for a PDF payload through the same "
        f"project and profile, got {document_response['semanticModality']!r} -- "
        "modality must track the actual bytes, not return a fixed value"
    )


def _create_project(ctx):
    ctrl = ctx.client("bedrock-data-automation")
    project_name = ctx.unique_name("sim2real-bda-proj-").replace("_", "-")[:128]
    resp = ctrl.create_data_automation_project(
        projectName=project_name,
        projectStage="LIVE",
        projectType="SYNC",
        standardOutputConfiguration={},
        tags=[{"key": "sim2real-created-by", "value": CHECK}],
    )
    project_arn = resp["projectArn"]
    ctx.on_cleanup(lambda: ctrl.delete_data_automation_project(projectArn=project_arn))
    return project_arn


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _profile_arn(ctx):
    suffix = _PROFILE_SUFFIX_BY_REGION.get(ctx.region)
    if suffix is None:
        raise AssertionError(
            f"region {ctx.region} is not one of the documented BDA cross-region-inference "
            "source regions; cannot construct a data-automation-profile ARN"
        )
    return f"arn:aws:bedrock:{ctx.region}:{_account_id(ctx)}:data-automation-profile/{suffix}"


def _minimal_png_bytes():
    return _generate_png_bytes()


_MINIMAL_PDF_B64 = (
    "JVBERi0xLjQKMSAwIG9iajw8IC9UeXBlIC9DYXRhbG9nIC9QYWdlcyAyIDAgUiA+PmVuZG9iagoy"
    "IDAgb2JqPDwgL1R5cGUgL1BhZ2VzIC9LaWRzIFszIDAgUl0gL0NvdW50IDEgPj5lbmRvYmoKMyAw"
    "IG9iajw8IC9UeXBlIC9QYWdlIC9QYXJlbnQgMiAwIFIgL01lZGlhQm94IFswIDAgMjAwIDIwMF0g"
    "Pj5lbmRvYmoKdHJhaWxlcjw8IC9Sb290IDEgMCBSID4+CiUlRU9G"
)


def _minimal_pdf_bytes():
    return base64.b64decode(_MINIMAL_PDF_B64)


def _generate_png_bytes(width=64, height=64, rgb=(200, 30, 30)):
    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(
            ">I", zlib.crc32(tag + data) & 0xFFFFFFFF
        )

    sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    row = bytes(rgb) * width
    raw = (b"\x00" + row) * height
    idat = zlib.compress(raw)
    return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
