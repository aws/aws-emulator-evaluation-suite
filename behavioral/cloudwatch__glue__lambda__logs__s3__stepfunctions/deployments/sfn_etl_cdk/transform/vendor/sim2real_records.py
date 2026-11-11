"""A vendored, pure-Python dependency of both ETL handlers.

Its purpose is structural: a Lambda whose code imports a second module cannot be deployed with
`Code.from_inline`, so the function can only exist through the asset-publishing path — cdk-assets
zips the handler directory, uploads it under its content hash and CloudFormation points the
function's Code at that object. Each handler directory carries its OWN copy, which is what lets the
check assert per-asset content addressing: bumping VERSION in one copy must republish that asset
alone and leave the other's object key untouched.
"""

NAME = "sim2real-records"
VERSION = "1.0.0"


def parse(text: str) -> list[dict]:
    """JSON-lines -> records, skipping blank lines. Raises on a malformed line, deliberately: a
    broken batch must fail the state that read it rather than silently produce fewer rows."""
    return [__import__("json").loads(line) for line in text.splitlines() if line.strip()]


def digest(record: dict) -> str:
    """A deterministic, dependency-free digest of a record's items."""
    acc = 11
    for key in sorted(record):
        for char in f"{key}={record[key]};":
            acc = (acc * 137 + ord(char)) % 0xFFFFFFFF
    return f"{NAME}:{VERSION}:{acc:08x}"
