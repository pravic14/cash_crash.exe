
import csv
from pathlib import Path

# Locate the generated CSV file
DATA_FILE = Path(__file__).parent / "data" / "transactions.csv"


def test_csv_exists():
    assert DATA_FILE.exists(), "Transaction CSV file was not created!"
    print("PASS: CSV file exists")


def test_csv_contents():
    with DATA_FILE.open("r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        transactions = list(reader)

    assert len(transactions) == 1500, (
        f"Expected 1500 transactions, but found {len(transactions)}"
    )
    assert sum(row["scenario_label"] == "normal" for row in transactions) == 1350
    assert sum(row["scenario_label"] == "suspicious" for row in transactions) == 150

    customer_counts = {}
    for transaction in transactions:
        customer_id = transaction["customer_id"]
        customer_counts[customer_id] = customer_counts.get(customer_id, 0) + 1

    assert len(customer_counts) == 5, (
        f"Expected 5 customers, but found {len(customer_counts)}"
    )
    assert set(customer_counts.values()) == {300}, (
        f"Expected 300 transactions per customer, got {customer_counts}"
    )
    print("PASS: Expected transaction and customer counts")

    required_columns = {
        "customer_id",
        "transaction_id",
        "timestamp",
        "amount",
        "payee_id",
        "is_new_payee",
        "reference",
        "scenario_label",
    }

    assert required_columns.issubset(reader.fieldnames), (
        "One or more required columns are missing"
    )
    print("PASS: Required columns exist")

    for transaction in transactions:
        assert float(transaction["amount"]) > 0, (
            f"Invalid amount in {transaction['transaction_id']}"
        )

    print("PASS: All transaction amounts are positive")

    transaction_ids = [
        transaction["transaction_id"] for transaction in transactions
    ]

    assert len(transaction_ids) == len(set(transaction_ids)), (
        "Duplicate transaction IDs found"
    )
    print("PASS: Transaction IDs are unique")


if __name__ == "__main__":
    test_csv_exists()
    test_csv_contents()
    print("\nAll generator tests passed!")
