"""managed-job-template-describable."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "managed-job-template-describable"
GROUP = 'job-lifecycle'
SERVICES = ['iot']

def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) of the ClientError it raises.

    Raises AssertionError when the call succeeds.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")

@tags("axis:happy-path", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AWS-managed job templates are listable and each is describable with a document."""
    iot = ctx.client("iot")
    templates = iot.list_managed_job_templates().get("managedJobTemplates", [])
    assert len(templates) >= 1, "AWS provides built-in managed job templates"

    name = templates[0]["templateName"]
    desc = iot.describe_managed_job_template(templateName=name)
    assert desc["templateName"] == name
    assert "document" in desc, desc.keys()
    raw_document = desc["document"]
    assert isinstance(raw_document, str) and raw_document.strip(), raw_document
    document = json.loads(raw_document)
    assert isinstance(document, dict) and "steps" in document, (
        f"managed job template document must be a job document with 'steps', got {document!r}"
    )

    # A managed template name that does not exist is a *validation* failure here, not a
    # 404 -- the name must match the managed catalog.
    missing = ctx.unique_name("no-such-managed-tmpl-")
    code, message = _err(lambda: iot.describe_managed_job_template(templateName=missing))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    expected = f"Invalid ManagedJobTemplate name: {missing}"
    assert message == expected, f"DescribeManagedJobTemplate message {message!r} != {expected!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
