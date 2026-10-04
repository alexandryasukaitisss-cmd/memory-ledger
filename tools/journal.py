"""Explicit-path SQLite backup, restore and raw export. Uses the standard library."""
import argparse
from contextlib import closing
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import sys


def absolute(value):
    path = Path(value)
    if not path.is_absolute():
        raise ValueError("Use an absolute path; no working-memory default is used")
    return path


def source(path):
    if not path.is_file():
        raise ValueError("Source database does not exist")
    db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    if db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
        db.close()
        raise ValueError("SQLite quick_check failed")
    return db


def private_output(path):
    if path.exists() or path.is_symlink():
        raise ValueError("Destination exists; refusing to overwrite it")
    if not path.parent.is_dir():
        raise ValueError("Create a private destination directory first")
    if os.name == "posix" and path.parent.stat().st_mode & 0o077:
        raise ValueError("Destination directory must have mode 0700")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    return os.fdopen(fd, "w", encoding="utf-8")


def copy_database(src, dest):
    # A coherent online backup includes committed WAL contents.
    with closing(source(src)) as origin:
        with private_output(dest):
            pass
        try:
            with closing(sqlite3.connect(dest)) as target:
                origin.backup(target)
                if target.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise ValueError("Backup integrity check failed")
        except BaseException:
            dest.unlink(missing_ok=True)  # Only our newly created destination.
            raise


def export_events(src, dest, before=None):
    if before:
        cutoff = datetime.fromisoformat(before.replace("Z", "+00:00"))
        if cutoff.tzinfo is None:
            raise ValueError("--before must include a UTC offset")
        before = cutoff.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    with closing(source(src)) as origin:
        origin.row_factory = sqlite3.Row
        sql = "SELECT * FROM memory_events"
        parameters = []
        if before:
            sql += " WHERE created_at < ?"
            parameters.append(before)
        sql += " ORDER BY created_at, id"
        output = private_output(dest)
        try:
            with output:
                count = 0
                for row in origin.execute(sql, parameters):
                    output.write(json.dumps(dict(row), ensure_ascii=False) + "\n")
                    count += 1
                output.flush()
                os.fsync(output.fileno())
        except BaseException:
            dest.unlink(missing_ok=True)
            raise
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["backup", "restore", "export"])
    parser.add_argument("--db", required=True, type=absolute)
    parser.add_argument("--to", required=True, type=absolute)
    parser.add_argument("--before", help="Export raw events before this ISO timestamp; no deletion")
    args = parser.parse_args()
    if args.before and args.operation != "export":
        parser.error("--before is only available for export")
    if args.operation == "export":
        count = export_events(args.db, args.to, args.before)
        print(json.dumps({"events": count, "destination": str(args.to), "raw_personal_data_possible": True}))
    else:
        copy_database(args.db, args.to)
        print(json.dumps({"destination": str(args.to), "integrity": "ok"}))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, sqlite3.Error) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
