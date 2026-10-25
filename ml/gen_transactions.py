
import csv
import random
from datetime import datetime, timedelta
from pathlib import Path



START_DATE = datetime(2026, 4, 1)
END_DATE = datetime(2026, 9, 30)

OUTPUT_FILE = Path(__file__).parent / "data" / "transactions.csv"

CUSTOMERS = [
    "acc-margaret",
    "acc-megan",
    "acc-kenneth",
    "acc-michael",
    "acc-mary",
]

TRANSACTIONS_PER_CUSTOMER = 300
SUSPICIOUS_PER_CUSTOMER = 30



NORMAL_PAYEES = [
    "payee-supermarket",
    "payee-transport",
    "payee-utilities",
    "payee-employer",
    "payee-landlord",
    "payee-coffee-shop",
    "payee-pharmacy",
    "payee-grocery-store",
    "payee-entertainment",
    "payee-internet-provider",
    "payee-gym",
    "payee-restaurant",
    "payee-mobile-provider",
    "payee-insurance",
    "payee-university",
    "payee-clothing-store",
    "payee-streaming-service",
    "payee-bookshop",
    "payee-charity",
    "payee-family",
]



NEW_PAYEES = [
    "payee-new-plumber",
    "payee-new-electrician",
    "payee-new-friend",
    "payee-new-shop",
    "payee-new-doctor",
    "payee-new-tutor",
    "payee-new-travel-agent",
    "payee-new-freelancer",
]


SUSPICIOUS_PAYEES = [
    "payee-mule",
    "payee-mule-001",
    "payee-mule-002",
    "payee-liquidator-001",
    "payee-unknown-001",
    "payee-unknown-002",
    "payee-safe-account-001",
    "payee-safe-account-002",
    "payee-fake-hmrc",
    "payee-fake-bank",
    "payee-investment-scam",
]


NORMAL_REFERENCES = [
    "Groceries",
    "Weekly shopping",
    "Electricity bill",
    "Monthly salary",
    "Monthly rent",
    "Coffee",
    "Pharmacy",
    "Water bill",
    "Internet bill",
    "Movie tickets",
    "Gym membership",
    "Restaurant",
    "Clothing",
    "Mobile bill",
    "Insurance payment",
    "University fees",
    "Family support",
    "Birthday gift",
    "Online order",
    "Travel booking",
    "Doctor appointment",
    "Plumbing repair",
    "Tutoring payment",
    "Subscription renewal",
    "Charity donation",
]


SUSPICIOUS_REFERENCES = [
    "Urgent safe account transfer",
    "HMRC refund verification",
    "Transfer money immediately",
    "Your account will be blocked",
    "Emergency payment required",
    "Secret government account",
    "Verify your bank account now",
    "Urgent security payment",
    "Immediate action required",
    "Confidential account transfer",
    "Avoid arrest by paying now",
    "Move funds to a protected account",
    "Your savings are at risk",
    "Pay a fee to release your refund",
    "Do not tell anyone about this",
    "Guaranteed investment return",
    "Final warning: act immediately",
    "Security team requests transfer",
]



CUSTOMER_PROFILES = {
    "acc-margaret": {
        "usual_amount": (15, 120),
        "large_amount": (500, 1100),
        "balance": 4200.0,
    },
    "acc-megan": {
        "usual_amount": (10, 180),
        "large_amount": (400, 1600),
        "balance": 2500.0,
    },
    "acc-kenneth": {
        "usual_amount": (20, 250),
        "large_amount": (700, 2200),
        "balance": 8000.0,
    },
    "acc-michael": {
        "usual_amount": (5, 100),
        "large_amount": (300, 900),
        "balance": 1500.0,
    },
    "acc-mary": {
        "usual_amount": (15, 200),
        "large_amount": (600, 1800),
        "balance": 5000.0,
    },
}


def random_timestamp(rng):
  

    total_days = (END_DATE - START_DATE).days

    date = START_DATE + timedelta(
        days=rng.randint(0, total_days)
    )

    return date.replace(
        hour=rng.randint(0, 23),
        minute=rng.choice([0, 10, 15, 20, 30, 40, 45, 50]),
        second=0,
        microsecond=0,
    )


def generate_normal_transaction(rng, customer, transaction_id):


    profile = CUSTOMER_PROFILES[customer]

   
    if rng.random() < 0.12:
        payee = rng.choice(NEW_PAYEES)
        is_new_payee = True
    else:
        payee = rng.choice(NORMAL_PAYEES)
        is_new_payee = False

    
    if payee == "payee-employer":
        amount = round(rng.uniform(1800, 3000), 2)

    elif payee == "payee-landlord" and customer == "acc-margaret":
        amount = round(rng.uniform(740, 760), 2)

    elif payee == "payee-landlord":
        amount = round(rng.uniform(450, 1200), 2)

    elif payee == "payee-university":
        amount = round(rng.uniform(200, 2500), 2)

    elif payee == "payee-insurance":
        amount = round(rng.uniform(30, 400), 2)

    else:
        amount = round(
            rng.uniform(*profile["usual_amount"]),
            2,
        )

    
    timestamp = random_timestamp(rng)
    message = "Monthly rent" if payee == "payee-landlord" else rng.choice(NORMAL_REFERENCES)
    reference = "RENT" if payee == "payee-landlord" else message[:18]

    return {
        "customer_id": customer,
        "transaction_id": transaction_id,
        "timestamp": timestamp.isoformat(),
        "amount": amount,
        "payee_id": payee,
        "is_new_payee": is_new_payee,
        "reference": reference,
        "message": message,
        "scenario_label": "normal",
    }


def generate_suspicious_transaction(rng, customer, transaction_id):
    

    profile = CUSTOMER_PROFILES[customer]

    scenario = rng.choice([
        "large_transfer",
        "new_recipient",
        "urgent_payment",
        "overnight_transfer",
        "moderate_transfer",
        "known_recipient",
    ])

    if scenario == "large_transfer":
        amount = round(rng.uniform(2000, 10000), 2)
        payee = rng.choice(SUSPICIOUS_PAYEES)
        is_new_payee = rng.random() < 0.75

    elif scenario == "new_recipient":
        amount = round(rng.uniform(100, 900), 2)
        payee = rng.choice(SUSPICIOUS_PAYEES)
        is_new_payee = True

    elif scenario == "urgent_payment":
        amount = round(rng.uniform(250, 2500), 2)
        payee = rng.choice(SUSPICIOUS_PAYEES)
        is_new_payee = rng.random() < 0.60

    elif scenario == "overnight_transfer":
        amount = round(rng.uniform(100, 1800), 2)
        payee = rng.choice(SUSPICIOUS_PAYEES)
        is_new_payee = rng.random() < 0.65

    elif scenario == "moderate_transfer":
        amount = round(rng.uniform(50, 500), 2)
        payee = rng.choice(SUSPICIOUS_PAYEES)
        is_new_payee = rng.random() < 0.70

    else:
        
        amount = round(
            rng.uniform(*profile["large_amount"]),
            2,
        )
        payee = rng.choice(NORMAL_PAYEES)
        is_new_payee = False

    timestamp = random_timestamp(rng)

   
    if scenario == "overnight_transfer":
        timestamp = timestamp.replace(
            hour=rng.choice([0, 1, 2, 3, 4, 5])
        )

    return {
        "customer_id": customer,
        "transaction_id": transaction_id,
        "timestamp": timestamp.isoformat(),
        "amount": amount,
        "payee_id": payee,
        "is_new_payee": is_new_payee,
        "reference": "URGENT"[:18],
        "message": rng.choice(SUSPICIOUS_REFERENCES),
        "scenario_label": "suspicious",
    }


def generate_transactions():
    

    rng = random.Random(42)
    transactions = []
    transaction_number = 1

    for customer in CUSTOMERS:
        suspicious_count = SUSPICIOUS_PER_CUSTOMER
        normal_count = (
            TRANSACTIONS_PER_CUSTOMER - suspicious_count
        )

        for _ in range(normal_count):
            transaction_id = f"TXN{transaction_number:05d}"

            transaction = generate_normal_transaction(
                rng,
                customer,
                transaction_id,
            )

            transactions.append(transaction)
            transaction_number += 1

        for _ in range(suspicious_count):
            transaction_id = f"TXN{transaction_number:05d}"

            transaction = generate_suspicious_transaction(
                rng,
                customer,
                transaction_id,
            )

            transactions.append(transaction)
            transaction_number += 1

    
    transactions.sort(
        key=lambda transaction: transaction["timestamp"]
    )

    return transactions


def save_transactions(transactions):
    

    fieldnames = [
        "customer_id",
        "transaction_id",
        "timestamp",
        "amount",
        "payee_id",
        "is_new_payee",
        "reference",
        "message",
        "scenario_label",
    ]

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with OUTPUT_FILE.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as csvfile:
        writer = csv.DictWriter(
            csvfile,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(transactions)


def main():
    transactions = generate_transactions()
    save_transactions(transactions)

    normal_count = 0
    suspicious_count = 0
    for transaction in transactions:
        if transaction["scenario_label"] == "normal":
            normal_count += 1
        elif transaction["scenario_label"] == "suspicious":
            suspicious_count += 1

    print("Customers:", len(CUSTOMERS))
    print("Transactions per customer:", TRANSACTIONS_PER_CUSTOMER)
    print("Normal transactions:", normal_count)
    print("Suspicious transactions:", suspicious_count)
    print("Total transactions:", len(transactions))
    print("Saved to:", OUTPUT_FILE)


if __name__ == "__main__":
    main()
