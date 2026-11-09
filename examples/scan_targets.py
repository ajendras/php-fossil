"""Example of using the PHP Fossil library API."""

import asyncio

from phpfossil import scan_targets, generate_report, store_results, get_historical_results
from phpfossil.models import ScanResult


async def main() -> None:
    """Run a demo scan and generate reports."""
    print("Starting PHP Fossil scan demo...")

    results = await scan_targets(
        ["https://httpbin.org", "http://example.com"],
        config={
            "max_concurrency": 5,
            "timeout": 10,
            "use_nuclei": False,
        },
    )

    # Results are automatically persisted
    store_results(results)

    generate_report(results, output_format="terminal")

    # Example of re-using historical data
    history = get_historical_results(limit=2)
    print(f"Retrieved {len(history)} historical scan(s) from SQLite store.")

    print("\nDemo completed successfully. Check ~/.phpfossil/history.db for persisted results.")


if __name__ == "__main__":
    asyncio.run(main())
