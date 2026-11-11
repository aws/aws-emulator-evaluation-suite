"""job-document-unicode-payload-round-trip."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "job-document-unicode-payload-round-trip"
GROUP = "representation"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A job document containing unicode text and special JSON characters is returned
    byte-identical by GetJobDocument, with no escaping/mutation of the stored content."""
    iot = ctx.client("iot")
    thing_name = ctx.unique_name("sim2real-jobdoc-thing-")
    thing_arn = iot.create_thing(thingName=thing_name)["thingArn"]
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))

    document = {
        "operation": "update",
        "unicode": "h\u00e9llo w\u00f6rld \u2014 \u65e5\u672c\u8a9e \U0001F680",
        "special": 'quote"backslash\\escaped-newline\\nliteral',
        "nested": {"list": [1, 2.5, "three", None, True]},
    }
    document_str = json.dumps(document, ensure_ascii=False)

    job_id = ctx.unique_name("sim2real-jobdoc-")
    iot.create_job(
        jobId=job_id,
        targets=[thing_arn],
        document=document_str,
        tags=[{"Key": "sim2real", "Value": "jobdoc-unicode-round-trip"}],
    )
    ctx.on_cleanup(lambda: iot.delete_job(jobId=job_id, force=True))

    returned = iot.get_job_document(jobId=job_id)["document"]
    assert returned == document_str, (
        f"document must round-trip byte-identical, got {returned!r}"
    )
    parsed = json.loads(returned)
    assert parsed == document, (
        f"round-tripped document must parse back to the original, got {parsed!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
