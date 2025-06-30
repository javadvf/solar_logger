#Developed by Javad Farahani - javadfarahani.com
import os
import csv
import json
import time
import hashlib
import traceback
from datetime import datetime
from collections import deque
from web3 import Web3
from merkletools import MerkleTools
import board
import busio
from adafruit_ina219 import INA219

from performance_logger import get_metrics, write_metrics, write_header_if_needed



# I2C setup (once, outside of function)
i2c_bus = busio.I2C(board.SCL, board.SDA)


for _ in range(3):  # Retry up to 3 times
    try:
        ina219 = INA219(i2c_bus)
        break
    except OSError as e:
        print(f"[INIT WARNING] INA219 setup failed (retrying): {e}")
        time.sleep(0.1)
else:
    print("[ERROR] INA219 initialization failed permanently.")
    ina219 = None



# Configuration
ENERGY_DIR = "energy_logs"
QUEUE_FILE = "unsubmitted_records.json"
PROOF_FILE = "proof_log.json"
PENDING_FILE = "pending_submission.json"
TOTAL_ENERGY_THRESHOLD = 0.001  # Wh
last_record_hash = "0" * 64  # Initial chain hash seed

current_utc_date = datetime.utcnow().date()  # Used to detect day change



DEVICE_ID = "device_001"
WEB3_PROVIDER = "https://sepolia.infura.io/v3/X"
CONTRACT_ADDRESS = "0xc986b14F1d8a26FB46b10D6fdA35C5D4062bDA98"
ACCOUNT_ADDRESS = "0x6A364d9376a1fbe0042871f136EA8FB240B44566"
PRIVATE_KEY = "X"
cumulative_energy_runtime = None

EVENT_LOG_FILE = "events_log.json"


# To ensure performance log file exists
PERF_LOG_FILE = "resource_usage_log.csv"
write_header_if_needed(PERF_LOG_FILE)



ABI = [
	{
		"anonymous": False,
		"inputs": [
			{
				"indexed": True,
				"internalType": "address",
				"name": "submitter",
				"type": "address"
			},
			{
				"indexed": True,
				"internalType": "uint256",
				"name": "index",
				"type": "uint256"
			},
			{
				"indexed": True,
				"internalType": "bytes32",
				"name": "deviceIdHash",
				"type": "bytes32"
			},
			{
				"indexed": False,
				"internalType": "bytes32",
				"name": "merkleRoot",
				"type": "bytes32"
			},
			{
				"indexed": False,
				"internalType": "bytes32",
				"name": "batchHash",
				"type": "bytes32"
			},
			{
				"indexed": False,
				"internalType": "uint256",
				"name": "timestamp",
				"type": "uint256"
			},
			{
				"indexed": False,
				"internalType": "string",
				"name": "deviceId",
				"type": "string"
			},
			{
				"indexed": False,
				"internalType": "uint256",
				"name": "cumulativeEnergyWh",
				"type": "uint256"
			}
		],
		"name": "BatchLogged",
		"type": "event"
	},
	{
		"inputs": [],
		"name": "getAllLogs",
		"outputs": [
			{
				"components": [
					{
						"internalType": "bytes32",
						"name": "merkleRoot",
						"type": "bytes32"
					},
					{
						"internalType": "bytes32",
						"name": "batchHash",
						"type": "bytes32"
					},
					{
						"internalType": "uint256",
						"name": "timestamp",
						"type": "uint256"
					},
					{
						"internalType": "bytes32",
						"name": "deviceIdHash",
						"type": "bytes32"
					},
					{
						"internalType": "string",
						"name": "deviceId",
						"type": "string"
					},
					{
						"internalType": "uint256",
						"name": "cumulativeEnergyWh",
						"type": "uint256"
					},
					{
						"internalType": "address",
						"name": "submitter",
						"type": "address"
					}
				],
				"internalType": "struct SolarLoggerV3.LogEntry[]",
				"name": "",
				"type": "tuple[]"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "index",
				"type": "uint256"
			}
		],
		"name": "getLog",
		"outputs": [
			{
				"internalType": "bytes32",
				"name": "merkleRoot",
				"type": "bytes32"
			},
			{
				"internalType": "bytes32",
				"name": "batchHash",
				"type": "bytes32"
			},
			{
				"internalType": "uint256",
				"name": "timestamp",
				"type": "uint256"
			},
			{
				"internalType": "bytes32",
				"name": "deviceIdHash",
				"type": "bytes32"
			},
			{
				"internalType": "string",
				"name": "deviceId",
				"type": "string"
			},
			{
				"internalType": "uint256",
				"name": "cumulativeEnergyWh",
				"type": "uint256"
			},
			{
				"internalType": "address",
				"name": "submitter",
				"type": "address"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "getTotalLogs",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "bytes32",
				"name": "merkleRoot",
				"type": "bytes32"
			},
			{
				"internalType": "bytes32",
				"name": "batchHash",
				"type": "bytes32"
			},
			{
				"internalType": "uint256",
				"name": "timestamp",
				"type": "uint256"
			},
			{
				"internalType": "bytes32",
				"name": "deviceIdHash",
				"type": "bytes32"
			},
			{
				"internalType": "string",
				"name": "deviceId",
				"type": "string"
			},
			{
				"internalType": "uint256",
				"name": "cumulativeEnergyWh",
				"type": "uint256"
			}
		],
		"name": "logBatch",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"name": "logs",
		"outputs": [
			{
				"internalType": "bytes32",
				"name": "merkleRoot",
				"type": "bytes32"
			},
			{
				"internalType": "bytes32",
				"name": "batchHash",
				"type": "bytes32"
			},
			{
				"internalType": "uint256",
				"name": "timestamp",
				"type": "uint256"
			},
			{
				"internalType": "bytes32",
				"name": "deviceIdHash",
				"type": "bytes32"
			},
			{
				"internalType": "string",
				"name": "deviceId",
				"type": "string"
			},
			{
				"internalType": "uint256",
				"name": "cumulativeEnergyWh",
				"type": "uint256"
			},
			{
				"internalType": "address",
				"name": "submitter",
				"type": "address"
			}
		],
		"stateMutability": "view",
		"type": "function"
	}
]

# Web3 setup
web3 = Web3(Web3.HTTPProvider(WEB3_PROVIDER))
contract = web3.eth.contract(address=Web3.to_checksum_address(CONTRACT_ADDRESS), abi=ABI)

# Ensure log directory exists
os.makedirs(ENERGY_DIR, exist_ok=True)

# Utils
def get_today_file():
    return os.path.join(ENERGY_DIR, f"energy_log_{datetime.utcnow().date()}.csv")

def get_timestamp():
    return datetime.utcnow().isoformat()

def sha256_str(s):
    return hashlib.sha256(s.encode('utf-8')).hexdigest()



def log_event(event_type, payload):
    try:
        # Ensure the directory exists
        dir_path = os.path.dirname(EVENT_LOG_FILE)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)

        # Load existing or create new
        events = load_json(EVENT_LOG_FILE, [])

        # Append the new event
        payload["event"] = event_type
        payload["timestamp"] = get_timestamp()
        events.append(payload)

        # Write to file safely
        with open(EVENT_LOG_FILE, "w") as f:
            json.dump(events, f, indent=2)

        print(f"[EVENT] Logged '{event_type}' with payload: {payload}")

    except Exception as e:
        # Optional: write to a fallback error log
        error_log_path = "event_log_errors.txt"
        with open(error_log_path, "a") as f:
            f.write(f"[{get_timestamp()}] Failed to log event: {event_type}\n")
            f.write(traceback.format_exc())
            f.write("\n---\n")
        print(f"[EVENT ERROR] Failed to log event '{event_type}': {e}")



def compute_chain_hash(records):
    """
    Computes a chained hash across records. Each hash includes the previous hash + current record string.
    :param records: list of dictionaries (records)
    :return: final chained hash (hex string)
    """
    previous_hash = "0" * 64  # Start with empty (zeroed) hash
    for record in records:
        content = ",".join(str(record.get(k, "0")) for k in [
            "timestamp", "voltage", "current", "power", "energy_Wh", "cumulative_energy_Wh", "device_id"
        ])
        chained_input = previous_hash + content
        current_hash = hashlib.sha256(chained_input.encode("utf-8")).hexdigest()
        previous_hash = current_hash
    return previous_hash



def rollover_unsubmitted_records_to_today():
    """
    Move any unsubmitted records from a previous day into today's CSV
    to ensure they eventually get hashed and submitted.
    """
    queue = load_json(QUEUE_FILE, [])
    if not queue:
        return


    today_str = datetime.utcnow().date().isoformat()
    today_file = get_today_file()

    # Read existing timestamps in today's file to avoid duplicates
    existing_timestamps = set()
    if os.path.exists(today_file):
        with open(today_file, "r") as f:
            for row in csv.DictReader(f):
                existing_timestamps.add(row["timestamp"])

    # Write old records into today's CSV if not already there
    written = 0
    with open(today_file, "a", newline="") as f:
        writer = None
        for record in queue:
            record_date = record["timestamp"][:10]
            if record_date < today_str and record["timestamp"] not in existing_timestamps:
                if writer is None:
                    writer = csv.DictWriter(f, fieldnames=record.keys())
                    if os.stat(today_file).st_size == 0:
                        writer.writeheader()
                writer.writerow(record)
                written += 1

    if written:
        print(f"[ROLLOVER] Migrated {written} unsubmitted records to {today_file}")
        log_event("rollover_migration", {
            "migrated_count": written,
            "target_file": today_file
        })




def measure_power():
    try:
        if ina219 is None:
            return {
                "timestamp": get_timestamp(),
                "voltage": 0.0,
                "current": 0.0,
                "power": 0.0
            }
        voltage = ina219.bus_voltage  # Volts
        current = ina219.current / 1000  # milliamps → amps
        power = voltage * current  # Watts

        return {
            "timestamp": get_timestamp(),
            "voltage": round(voltage, 3),
            "current": round(current, 3),
            "power": round(power, 3)
        }
    except Exception as e:
        print(f"[ERROR] INA219 read failed: {e}")
        return {
            "timestamp": get_timestamp(),
            "voltage": 0.0,
            "current": 0.0,
            "power": 0.0
        }

import shutil
def backup_logs():
    if os.path.exists(PROOF_FILE):
        shutil.copy(PROOF_FILE, PROOF_FILE + ".bak")
    today_csv = get_today_file()
    if os.path.exists(today_csv):
        shutil.copy(today_csv, today_csv + ".bak")


def load_json(filepath, default):
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except:
        return default

def save_json(filepath, data):
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)

def read_last_cumulative():
    file = get_today_file()
    if not os.path.exists(file):
        return 0.0
    with open(file, "r") as f:
        lines = f.readlines()
        if len(lines) <= 1:
            return 0.0
        header = lines[0].strip().split(",")
        last_row = lines[-1].strip().split(",")
        try:
            idx = header.index("cumulative_energy_Wh")
            return float(last_row[idx])
        except (ValueError, IndexError):
            return 0.0


def write_csv_row(record):
    file = get_today_file()
    write_header = not os.path.exists(file)
    with open(file, "a", newline="") as f:
        writer = csv.writer(f)
        if write_header:
            writer.writerow(record.keys())
        writer.writerow(record.values())

def append_unsubmitted(record):
    queue = load_json(QUEUE_FILE, [])
    queue.append(record)
    save_json(QUEUE_FILE, queue)



def update_proof_log(merkle_root, batch_hash, size, csv_file, tx_hash, cumulative_energy, row_start, row_end):
    proof_log = load_json(PROOF_FILE, [])

    try:
        with open(csv_file, "rb") as f:
            csv_hash = hashlib.sha256(f.read()).hexdigest()
    except Exception as e:
        print(f"[WARNING] Could not compute SHA256 of CSV file: {e}")
        csv_hash = "ERROR"

    proof_log.append({
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "root": merkle_root,
        "batch_hash": batch_hash,
        "size": size,
        "csv_path": csv_file,
        "csv_sha256": csv_hash,
        "tx_hash": tx_hash,
        "cumulative_energy_mWh": cumulative_energy,
        "row_start": row_start,
        "row_end": row_end
    })

    save_json(PROOF_FILE, proof_log)
    backup_logs()




def get_previous_merkle_root():
    logs = load_json(PROOF_FILE, [])
    if isinstance(logs, list) and logs:
        return logs[-1].get("root", "")
    return ""


def submit_to_blockchain(merkle_root, batch_hash, timestamp, deviceIdHash, deviceId, cumulativeEnergyWh):

    # Ensure '0x' prefix
    if not merkle_root.startswith("0x"):
        merkle_root = "0x" + merkle_root
    if not batch_hash.startswith("0x"):
        batch_hash = "0x" + batch_hash
    entry_count = len(load_json(QUEUE_FILE, []))  # number of queued records

    # Use pending nonce and bump gas price to avoid "replacement transaction underpriced"
    pending_nonce = web3.eth.get_transaction_count(ACCOUNT_ADDRESS, "pending")
    current_gas_price = web3.eth.gas_price
    bumped_gas_price = int(current_gas_price * 1.3) + web3.to_wei(3, "gwei")
    print(f"[BLOCKCHAIN] Gas Price Used: {web3.from_wei(bumped_gas_price, 'gwei')} gwei")

    if not merkle_root.startswith("0x"):
        merkle_root = "0x" + merkle_root
    if not batch_hash.startswith("0x"):
        batch_hash = "0x" + batch_hash

    print("[DEBUG] TX PARAMS:")
    print(" - merkle_root:", merkle_root, type(merkle_root))
    print(" - batch_hash:", batch_hash, type(batch_hash))
    print(" - timestamp:", timestamp, type(timestamp))
    print(" - cumulativeEnergyWh:", cumulativeEnergyWh, type(cumulativeEnergyWh))


    merkle_root_bytes = bytes.fromhex(merkle_root[2:] if merkle_root.startswith("0x") else merkle_root)
    batch_hash_bytes = bytes.fromhex(batch_hash[2:] if batch_hash.startswith("0x") else batch_hash)

    assert isinstance(merkle_root, str), "merkle_root must be string"
    assert isinstance(batch_hash, str), "batch_hash must be string"
    assert isinstance(timestamp, int), "timestamp must be int"
    assert isinstance(deviceIdHash, bytes), "deviceIdHash must be bytes"
    assert isinstance(deviceId, str), "deviceId must be string"
    assert isinstance(cumulativeEnergyWh, int), "cumulativeEnergyWh must be int"

    tx = contract.functions.logBatch(
        merkle_root_bytes,
        batch_hash_bytes,
        int(timestamp),
        deviceIdHash,
        deviceId,
        cumulativeEnergyWh
    ).build_transaction({
        "from": ACCOUNT_ADDRESS,
        "nonce": pending_nonce,
        "gas": 300000,
        "gasPrice": bumped_gas_price
    })




    # Check ETH balance
    balance = web3.eth.get_balance(ACCOUNT_ADDRESS)
    if balance < web3.to_wei("0.001", "ether"):
        raise Exception("Insufficient ETH balance for transaction.")

    # Sign and send transaction
    signed = web3.eth.account.sign_transaction(tx, PRIVATE_KEY)
    tx_hash = web3.eth.send_raw_transaction(signed.rawTransaction)

    return tx_hash.hex()


from hexbytes import HexBytes

def serialize_bytes(d):
    def safe_hex(v):
        if isinstance(v, (bytes, HexBytes)):
            return "0x" + v.hex()
        if isinstance(v, str) and len(v) == 64 and not v.startswith("0x"):
            return "0x" + v
        return v

    return {k: safe_hex(v) for k, v in d.items()}




def retry_pending_submission():
    pending = load_json(PENDING_FILE, {})
    if not pending:
        return
    print("[RETRY] Attempting to resubmit pending transaction...")
    try:
        print("[DEBUG] Pending submission data:", pending)
        if "deviceIdHash" in pending and isinstance(pending["deviceIdHash"], str):
            pending["deviceIdHash"] = bytes.fromhex(pending["deviceIdHash"].replace("0x", ""))

        # hotfix key rename if leftover field exists
        if "cumulative_energy" in pending:
            pending["cumulativeEnergyWh"] = pending.pop("cumulative_energy")

        tx_hash = submit_to_blockchain(**pending)

        save_json(PENDING_FILE, {})  # Clear if successful
        print(f"[RETRY] Pending tx resubmitted. Tx hash: {tx_hash}")
        log_event("retry_success", {"tx_hash": tx_hash})

    except Exception as e:
        print(f"[RETRY]  Failed again: {e}")


def logger_loop():
    global cumulative_energy_runtime, current_utc_date
    today = datetime.utcnow().date()
    if today != current_utc_date:
        print(f"[DAY CHANGE] New day detected: {today} (was {current_utc_date})")
        rollover_unsubmitted_records_to_today()
        current_utc_date = today

    if cumulative_energy_runtime is None:
        cumulative_energy_runtime = read_last_cumulative()
    print(f"[DATA] Last cumulative energy: {cumulative_energy_runtime:.8f} Wh")
    retry_pending_submission()
    power_data = measure_power()
    power = power_data["power"]
    energy = power / 60  # Wh
    if energy < 0:
        print(f"[WARNING] Negative energy reading skipped: {energy} Wh")
        energy = 0.0


    cumulative_energy_runtime += energy
    cumulative_energy_runtime = max(0.0, cumulative_energy_runtime)

    print(f"[SENSOR] Measured: V={power_data['voltage']} V, I={power_data['current']} A, P={power_data['power']} W")

    record = {
        **power_data,
        "energy_Wh": round(energy, 8),
        "cumulative_energy_Wh": round(cumulative_energy_runtime, 8),
        "device_id": DEVICE_ID
    }
    global last_record_hash
    # Chain hash: link to previous record
    content = ",".join(str(record.get(k, "0")) for k in [
        "timestamp", "voltage", "current", "power", "energy_Wh", "cumulative_energy_Wh", "device_id"
    ])
    chained_input = last_record_hash + content
    current_chain_hash = hashlib.sha256(chained_input.encode("utf-8")).hexdigest()
    record["chain_hash"] = current_chain_hash
    last_record_hash = current_chain_hash

    write_csv_row(record)
    print(f"[LOG] Writing record: {record}")
    append_unsubmitted(record)
    queue = load_json(QUEUE_FILE, [])
    total_energy = sum(r["energy_Wh"] for r in queue)
    print(f"[QUEUE] Total queued energy: {total_energy:.4f} Wh")
    if total_energy >= TOTAL_ENERGY_THRESHOLD:
        print(f"[MERKLE] Threshold reached. Preparing Merkle tree for {len(queue)} entries...")
        mt = MerkleTools(hash_type="sha256")
        for r in queue:
            leaf = ",".join(str(r.get(k, "0")) for k in ["timestamp", "voltage", "current", "power", "energy_Wh", "cumulative_energy_Wh", "device_id", "chain_hash"])

            mt.add_leaf(sha256_str(leaf), do_hash=False)
        mt.make_tree()
        merkle_root = mt.get_merkle_root()
        if not merkle_root:
            print("[ERROR] Merkle root is empty. Skipping submission.")
            return

        batch_hash = sha256_str(json.dumps(queue))
        timestamp = datetime.utcnow().timestamp()
        print(f"[MERKLE] Root: {merkle_root}")
        print(f"[BLOCKCHAIN] Submitting to blockchain...")
        
        if not merkle_root.startswith("0x"):
            merkle_root = "0x" + merkle_root
        if not batch_hash.startswith("0x"):
            batch_hash = "0x" + batch_hash

        tx_data = {
            "merkle_root": merkle_root,
            "batch_hash": batch_hash,
            "timestamp": int(timestamp),
            "deviceIdHash": Web3.keccak(text=DEVICE_ID),
            "deviceId": DEVICE_ID,
            "cumulativeEnergyWh": int(round(cumulative_energy_runtime * 1000))
        }



        try:
            tx_hash = submit_to_blockchain(**tx_data)

            csv_file_path = get_today_file()
            with open(csv_file_path, "r") as f:
                line_count = sum(1 for _ in f)

            today_file = get_today_file()
            with open(today_file, "r") as f:
                row_count = sum(1 for _ in f) - 1  # minus header

            row_end = row_count - 1
            row_start = row_end - len(queue) + 1

            update_proof_log(
                merkle_root=merkle_root,
                batch_hash=batch_hash,
                size=len(queue),
                csv_file=today_file,
                tx_hash=tx_hash,
                cumulative_energy=int(round(cumulative_energy_runtime * 1000)),
                row_start=row_start,
                row_end=row_end
            )



            save_json(QUEUE_FILE, [])  # Clear queue
            save_json(PENDING_FILE, {})  # Clear pending
            print(f"[BLOCKCHAIN]  Success! Tx hash: {tx_hash}")
            print(f"[BLOCKCHAIN] Confirmed tx submitted! View at: https://sepolia.etherscan.io/tx/{tx_hash}")
            

        except Exception as e:
            print(f"[BLOCKCHAIN]  Submission failed: {e}")            
            log_event("blockchain_submission_failed", {
                "reason": str(e),
                "details": {
                    "queued_entries": len(queue),
                    "cumulative_energy_mWh": int(round(cumulative_energy_runtime * 1000))
                }
            })
            save_json(PENDING_FILE, serialize_bytes(tx_data))

    #Track performance
    res_data = get_metrics()
    write_metrics(PERF_LOG_FILE, res_data)
    print(f"[PERF] Logged system metrics at {res_data['timestamp']}")



if __name__ == "__main__":
    rollover_unsubmitted_records_to_today()  # ensure boot-time safety
    while True:  
        start = time.time()
        logger_loop()
        elapsed = time.time() - start
        time.sleep(max(0, 60 - elapsed))


