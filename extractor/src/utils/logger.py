import logging
import os


class TrapLogger(logging.Logger):
    TRAP_LEVEL_NUM = logging.INFO

    def __init__(self, name: str, log_file: str, level: str | int | None = None):
        """`level` defaults to `BINQL_LOG_LEVEL`, else INFO."""
        # Determine logging level
        if level is None:
            env_level = os.environ.get("BINQL_LOG_LEVEL", "INFO").upper()
            level = getattr(logging, env_level, logging.INFO)

        super().__init__(name, level)

        # Register TRAP level once
        if logging.getLevelName(self.TRAP_LEVEL_NUM) != "TRAP":
            logging.addLevelName(self.TRAP_LEVEL_NUM, "TRAP")

        # File handler
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        file_handler = logging.FileHandler(log_file, mode="a")
        formatter = logging.Formatter("%(levelname)s - %(message)s")
        file_handler.setFormatter(formatter)
        self.addHandler(file_handler)

        # Per-level sibling files ("error", "warning", "debug") next to the
        # combined log: each holds only its own level's records, so a consumer
        # never has to parse level prefixes out of the mixed stream (and a
        # multi-line message / TRAP tuple can't be miscategorised).
        log_dir = os.path.dirname(log_file)
        for _name, _lvl in (
            ("error", logging.ERROR),
            ("warning", logging.WARNING),
            ("debug", logging.DEBUG),
        ):
            per = logging.FileHandler(os.path.join(log_dir, _name), mode="a")
            per.setLevel(_lvl)
            per.addFilter(lambda rec, _l=_lvl: rec.levelno == _l)
            per.setFormatter(formatter)
            self.addHandler(per)

        # Console handler (optional, can remove if you only want file logging)
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.addHandler(console_handler)

    def trap(self, message, *args, **kwargs):
        if self.isEnabledFor(self.TRAP_LEVEL_NUM):
            self._log(self.TRAP_LEVEL_NUM, message, args, **kwargs)

    def flush(self):
        for handler in self.handlers:
            handler.flush()

    @classmethod
    def from_env(cls, name: str = "BINQL", filename: str = "main") -> "TrapLogger":
        """Logger writing to `$BINQL_EXTRACTOR_LOG/<filename>` (default dir `/tmp/binql-log-extractor`)."""
        log_dir = os.environ.get("BINQL_EXTRACTOR_LOG", "/tmp/binql-log-extractor")
        log_file = os.path.join(log_dir, filename)
        return cls(name, log_file)
