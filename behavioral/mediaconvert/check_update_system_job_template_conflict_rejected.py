"""update-system-job-template-conflict-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-system-job-template-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediaconvert"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A built-in SYSTEM job template can't be modified by the user -- UpdateJobTemplate on one
    must be rejected and its Description must be unchanged. A CUSTOM template, by contrast,
    updates cleanly (the positive control)."""
    mc = ctx.client("mediaconvert")

    system_templates: list = []
    token = None
    for _ in range(25):
        params = {"ListBy": "SYSTEM", "MaxResults": 20}
        if token:
            params["NextToken"] = token
        resp = mc.list_job_templates(**params)
        system_templates.extend(resp.get("JobTemplates", []))
        token = resp.get("NextToken")
        if not token:
            break
    if not system_templates:
        raise AssertionError(
            "account has no SYSTEM job templates to test immutability against; would be closed "
            "by an account/region that has the built-in MediaConvert system templates enabled"
        )
    target = system_templates[0]["Name"]
    before = mc.get_job_template(Name=target)["JobTemplate"]

    code, message = _error(lambda: mc.update_job_template(Name=target, Description="sim2real-attempt"))
    assert code == "ForbiddenException", f"expected ForbiddenException, got {code!r}"
    expected = "You are not allowed to update system job templates."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    after = mc.get_job_template(Name=target)["JobTemplate"]
    assert after.get("Description") == before.get("Description")

    # positive control: a custom template updates cleanly
    custom_name = ctx.unique_name("sim2real-mc-tmpl-")
    mc.create_job_template(
        Name=custom_name,
        Settings={
            "OutputGroups": [
                {
                    "Name": "File Group",
                    "OutputGroupSettings": {
                        "Type": "FILE_GROUP_SETTINGS",
                        "FileGroupSettings": {"Destination": "s3://sim2real-mc-placeholder/out/"},
                    },
                    "Outputs": [
                        {
                            "ContainerSettings": {"Container": "MP4"},
                            "VideoDescription": {
                                "CodecSettings": {
                                    "Codec": "H_264",
                                    "H264Settings": {
                                        "RateControlMode": "QVBR",
                                        "QvbrSettings": {"QvbrQualityLevel": 7},
                                        "MaxBitrate": 5000000,
                                        "SceneChangeDetect": "ENABLED",
                                    },
                                }
                            },
                        }
                    ],
                }
            ]
        },
    )
    ctx.on_cleanup(lambda: mc.delete_job_template(Name=custom_name))
    mc.update_job_template(Name=custom_name, Description="sim2real-updated")
    updated = mc.get_job_template(Name=custom_name)["JobTemplate"]
    assert updated["Description"] == "sim2real-updated"


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises rather
    than returning a falsy sentinel."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
