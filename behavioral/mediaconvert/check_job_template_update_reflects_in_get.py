"""job-template-update-reflects-in-get."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "job-template-update-reflects-in-get"
GROUP = "state"
SERVICES = ["mediaconvert"]
NOT_FOUND_MESSAGE = "The resource you specified in name was not found."


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateJobTemplate's Priority 0 -> 10 and Category cat-a -> cat-b show on GetJobTemplate with a
    LastUpdated that does not go back, and after DeleteJobTemplate both GetJobTemplate and
    UpdateJobTemplate fail NotFoundException with the exact message."""
    mc = ctx.client("mediaconvert")
    name = ctx.unique_name("sim2real-mc-tmpl-")
    bucket = ctx.unique_name("sim2real-mc-bucket-")
    mc.create_job_template(
        Name=name,
        Settings={"OutputGroups": _output_groups(f"s3://{bucket}/out/")},
        Priority=0,
        Category="cat-a",
        Tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: _safe_cleanup(lambda: mc.delete_job_template(Name=name)))

    before = mc.get_job_template(Name=name)["JobTemplate"]
    assert before["Priority"] == 0, f"expected initial Priority 0, got {before['Priority']!r}"
    assert before["Category"] == "cat-a", f"expected initial Category 'cat-a', got {before['Category']!r}"

    mc.update_job_template(Name=name, Priority=10, Category="cat-b")
    after = mc.get_job_template(Name=name)["JobTemplate"]
    assert after["Priority"] == 10, f"expected updated Priority 10, got {after['Priority']!r}"
    assert after["Category"] == "cat-b", f"expected updated Category 'cat-b', got {after['Category']!r}"
    assert after["LastUpdated"] >= before["LastUpdated"], (
        f"LastUpdated must not go backwards after UpdateJobTemplate: "
        f"before={before['LastUpdated']!r} after={after['LastUpdated']!r}"
    )

    mc.delete_job_template(Name=name)
    code, message = _error(lambda: mc.get_job_template(Name=name))
    assert code == "NotFoundException", f"expected GetJobTemplate on a deleted template to fail NotFoundException, got {code!r}"
    assert message == NOT_FOUND_MESSAGE, f"expected message {NOT_FOUND_MESSAGE!r}, got {message!r}"
    code2, message2 = _error(lambda: mc.update_job_template(Name=name, Priority=1))
    assert code2 == "NotFoundException", f"expected UpdateJobTemplate on a deleted template to fail NotFoundException, got {code2!r}"
    assert message2 == NOT_FOUND_MESSAGE, f"expected message {NOT_FOUND_MESSAGE!r}, got {message2!r}"


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises rather
    than returning a falsy sentinel."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_cleanup(fn) -> None:
    try:
        fn()
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


def _output_groups(output_uri: str) -> list:
    return [
        {
            "Name": "File Group",
            "OutputGroupSettings": {
                "Type": "FILE_GROUP_SETTINGS",
                "FileGroupSettings": {"Destination": output_uri},
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
