"""Command-line entrypoint for Artifact Two verification."""

from __future__ import annotations

import argparse
import json
import sys

from .verifier import VerificationPolicy, verify_bundle


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify an ATP receipt bundle")
    parser.add_argument("bundle", help="Path to a receipt bundle directory")
    parser.add_argument(
        "--max-clock-skew-sec",
        type=int,
        default=None,
        help="Optionally reject archived bundles whose envelope createdAt is too far from now",
    )
    parser.add_argument(
        "--enforce-envelope-expiry",
        action="store_true",
        help="Reject envelopes whose expiresAt is in the past",
    )
    parser.add_argument(
        "--strict-denials",
        action="store_true",
        help="Reject all denied lease log entries, including demo negative-test writes",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    policy = VerificationPolicy(
        allow_expected_denied_write=not args.strict_denials,
        max_clock_skew_sec=args.max_clock_skew_sec,
        enforce_envelope_expiry=args.enforce_envelope_expiry,
    )
    result = verify_bundle(args.bundle, policy)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["reason_code"] == "OK" else 1


if __name__ == "__main__":
    sys.exit(main())
