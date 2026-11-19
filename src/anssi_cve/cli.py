"""Command-line entry point: `anssi-cve` or `python -m anssi_cve`."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from . import __version__
from .config import FEEDS
from .http import build_session
from .pipeline import run


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="anssi-cve",
        description=(
            "Collect CERT-FR bulletins and enrich their CVEs with MITRE and FIRST EPSS data."
        ),
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("output/anssi_cve.csv"),
        help="output file, .csv or .json (default: output/anssi_cve.csv)",
    )
    parser.add_argument(
        "--feeds",
        nargs="+",
        choices=[name.lower() for name in FEEDS],
        default=[name.lower() for name in FEEDS],
        help="feeds to process (default: all)",
    )
    parser.add_argument("--limit", type=int, help="max bulletins per feed (handy for a quick test)")
    parser.add_argument(
        "--workers", type=int, default=8, help="parallel HTTP requests (default: 8)"
    )
    parser.add_argument(
        "--min-cvss", type=float, help="only keep CVEs with a CVSS score at or above this value"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    feed_names = [name for name in FEEDS if name.lower() in args.feeds]

    df = run(build_session(), feed_names, limit=args.limit, workers=args.workers)
    if args.min_cvss is not None:
        df = df[df["CVSS"] >= args.min_cvss]

    args.output.parent.mkdir(parents=True, exist_ok=True)
    suffix = args.output.suffix.lower()
    if suffix == ".json":
        df.to_json(args.output, orient="records", force_ascii=False, indent=2, date_format="iso")
    elif suffix == ".csv":
        # utf-8-sig so accented column names open cleanly in Excel
        df.to_csv(args.output, index=False, encoding="utf-8-sig")
    else:
        logging.error("Unsupported output format %r, use .csv or .json", suffix)
        return 2

    logging.info("Wrote %d rows to %s", len(df), args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
