class BridgeError(Exception):
    """Expected refusal with a fixed, non-sensitive public error code."""

    def __init__(self, code: str, *, upstream: bool = False) -> None:
        self.code = code
        self.upstream = upstream
        super().__init__(code)
