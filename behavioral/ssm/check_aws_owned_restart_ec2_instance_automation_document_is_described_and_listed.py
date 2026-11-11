"""aws-owned-restart-ec2-instance-automation-document-is-described-and-listed."""

from __future__ import annotations

from behavioral_harness import tags

CHECK = "aws-owned-restart-ec2-instance-automation-document-is-described-and-listed"
GROUP = "documents"
SERVICES = ["ssm"]

_DOCUMENT = "AWS-RestartEC2Instance"
#: (Owner, DocumentType, Status) DescribeDocument reports for the AWS-owned document.
_EXPECTED = ("Amazon", "Automation", "Active")


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AWS-RestartEC2Instance is an Active Automation document owned by Amazon.

    ListDocuments filtered to Owner Amazon and DocumentType Automation lists it.
    Reference: https://docs.aws.amazon.com/systems-manager-automation-runbooks/latest/userguide/automation-aws-restartec2instance.html
    """
    ssm = ctx.client("ssm")

    doc = ssm.describe_document(Name=_DOCUMENT)["Document"]
    described = (doc["Owner"], doc["DocumentType"], doc["Status"])
    assert (doc["Name"], described) == (_DOCUMENT, _EXPECTED), (
        f"DescribeDocument {_DOCUMENT} must report (Owner, DocumentType, Status) {_EXPECTED!r}; "
        f"got Name={doc['Name']!r} {described!r}"
    )

    listed = [
        (d["Owner"], d["DocumentType"])
        for page in ssm.get_paginator("list_documents").paginate(
            Filters=[
                {"Key": "Owner", "Values": ["Amazon"]},
                {"Key": "DocumentType", "Values": ["Automation"]},
                {"Key": "Name", "Values": [_DOCUMENT]},
            ]
        )
        for d in page["DocumentIdentifiers"]
        if d["Name"] == _DOCUMENT
    ]
    assert listed == [_EXPECTED[:2]], (
        f"ListDocuments filtered to Owner Amazon and DocumentType Automation must list "
        f"{_DOCUMENT} once with (Owner, DocumentType) {_EXPECTED[:2]!r}; got {listed!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
