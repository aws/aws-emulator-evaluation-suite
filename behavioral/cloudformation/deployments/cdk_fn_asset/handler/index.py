def handler(event, context):
    """The byte the determinism check flips lives on the next line."""
    return {"variant": "a", "n": len(event.get("items", []))}
