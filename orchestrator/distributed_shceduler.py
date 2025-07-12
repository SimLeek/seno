import time
import threading
import subprocess
import json
import socket
import hashlib
import logging
from dataclasses import dataclass, asdict
from typing import List, Dict, Any
from ortools.sat.python import cp_model
from collections import defaultdict

# Setup logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


# Dataclasses
@dataclass
class NetworkConfig:
    max_input_bandwidth_bps: int
    max_output_bandwidth_bps: int
    average_latency_ms: float


@dataclass
class GPU:
    cores: int
    ghz: float
    has_cuda: bool


@dataclass
class Machine:
    id: str
    ip: str
    cpu_cores: int
    cpu_ghz: float
    ram_gb: int
    vram_gb: int = 0
    gpus: List[GPU] = None
    devices: List[str] = None
    network: NetworkConfig = None

    def __post_init__(self):
        if self.gpus is None:
            self.gpus = []
        if self.devices is None:
            self.devices = []
        if self.network is None:
            self.network = NetworkConfig(0, 0, 0.0)


@dataclass
class Program:
    name: str
    required_devices: List[str]
    cpu_cores: float
    ram_gb: int
    network_bandwidth_bps: int
    priority: int
    path: str
    vram_gb: int = 0
    run_on_all_machines: bool = False


#@dataclass
#class ResourceMessage:
#    type: str
#    id: str
#    ip: str
#    cpu_cores: int
#    cpu_ghz: float
#    ram_gb: int
#    vram_gb: int
#    gpus: List[Dict[str, Any]]
#    devices: List[str]
#    network: Dict[str, Any]


@dataclass
class ScheduleHashMessage:
    type: str
    sender: str
    hash: str


@dataclass
class HeartbeatMessage:
    type: str
    id: str


@dataclass
class StartupPingMessage:
    type: str
    id: str


@dataclass
class StartupPongMessage:
    type: str
    id: str

@dataclass
class ScheduleHashMessage:
    type: str
    sender: str
    fingerprint: str  # Changed from hash to fingerprint
    assignment: Dict[str, str]  # Add the actual assignment for verification

# Load configuration
with open("config.json", "r") as f:
    CONFIG = json.load(f)

# Convert config to dataclasses
MACHINES = {
    k: Machine(
        id=v["id"],
        ip=v["ip"],
        cpu_cores=v["cpu_cores"],
        cpu_ghz=v["cpu_ghz"],
        ram_gb=v["ram_gb"],
        vram_gb=v.get("vram_gb", 0),
        gpus=[GPU(**gpu) for gpu in v.get("gpus", [])],
        devices=v["devices"],
        network=NetworkConfig(**v["network"]),
    )
    for k, v in CONFIG["machines"].items()
}
PROGRAMS = [
    Program(
        **{k: v for k, v in prog.items() if k != "run_on_all_machines"},
        run_on_all_machines=prog.get("run_on_all_machines", False),
    )
    for prog in CONFIG["programs"]
]
LOCAL_ID = CONFIG["local_id"]

# Global state
resource_view = {}
schedule_hashes = {}
heartbeats = {}
running_programs = {}
current_schedule = None
startup_responses = {}
orchestration_started = False

schedule_agreement_lock = threading.Lock()
schedule_fingerprints = {}
schedule_agreement_event = threading.Event()

def get_local_resources() -> Machine:
    """Gather local resource information."""
    return MACHINES[LOCAL_ID]


def can_run(program: Program, machine: Machine) -> bool:
    """Check if a program can run on a machine based on device requirements."""
    required_devices = set(program.required_devices)
    available_devices = set(machine.devices)
    yes_can_run = required_devices.issubset(available_devices)
    if not yes_can_run:
        print(f"p{program.name},m{machine.id} cannot run. missing requirements: {required_devices.difference(available_devices)}")
    return yes_can_run


def compute_schedule(
        machines: List[Machine], programs: List[Program]
) -> tuple[Dict[str, str], str]:
    """Compute optimal program assignment using OR-Tools."""
    model = cp_model.CpModel()
    x = {}

    # Variables: x[(program_name, machine_id)] = 1 if program assigned to machine
    for p in programs:
        for m in machines:
            if can_run(p, m):
                x[(p.name, m.id)] = model.NewBoolVar(f"x_{p.name}_{m.id}")

    # Constraints
    for p in programs:
        if p.run_on_all_machines:
            for m in machines:
                if can_run(p, m):
                    model.Add(x[(p.name, m.id)] == 1)
        else:
            model.Add(
                sum(x[(p.name, m.id)] for m in machines if (p.name, m.id) in x) <= 1
            )

    # Priority 100 programs must be assigned if compatible machine exists
    for p in programs:
        if p.priority == 100 and not p.run_on_all_machines:
            model.Add(
                sum(x[(p.name, m.id)] for m in machines if (p.name, m.id) in x) == 1
            )

    # Resource constraints per machine
    for m in machines:
        # CPU cores
        model.Add(
            sum(
                x[(p.name, m.id)] * int(p.cpu_cores)
                for p in programs
                if (p.name, m.id) in x
            )
            <= m.cpu_cores
        )
        # RAM
        model.Add(
            sum(
                x[(p.name, m.id)] * int(p.ram_gb)
                for p in programs
                if (p.name, m.id) in x
            )
            <= m.ram_gb
        )
        # VRAM (only apply if machine has VRAM)
        if m.vram_gb > 0:
            model.Add(
                sum(
                    x[(p.name, m.id)] * int(p.vram_gb)
                    for p in programs
                    if (p.name, m.id) in x
                )
                <= m.vram_gb
            )
        # Network bandwidth
        model.Add(
            sum(
                x[(p.name, m.id)] * int(p.network_bandwidth_bps)
                for p in programs
                if (p.name, m.id) in x
            )
            <= m.network.max_input_bandwidth_bps
        )
        # GPUs
        if m.gpus:
            model.Add(
                sum(
                    x[(p.name, m.id)]
                    for p in programs
                    if (p.name, m.id) in x and "gpu" in p.required_devices
                )
                <= len(m.gpus)
            )

    # Objective: Maximize sum of priorities
    objective = sum(
        x[(p.name, m.id)] * int(p.priority)
        for p in programs
        for m in machines
        if (p.name, m.id) in x
    )
    model.Maximize(objective)

    # Solve
    solver = cp_model.CpSolver()
    solver.parameters.log_search_progress = True
    status = solver.Solve(model)

    if status == cp_model.OPTIMAL or status == cp_model.FEASIBLE:
        assignment = {}
        unassigned = [p.name for p in programs if not p.run_on_all_machines]
        for p in programs:
            for m in machines:
                if (p.name, m.id) in x and solver.Value(x[(p.name, m.id)]) > 0:
                    assignment[
                        f"{p.name}_{m.id}" if p.run_on_all_machines else p.name
                    ] = m.id
                    if not p.run_on_all_machines and p.name in unassigned:
                        unassigned.remove(p.name)

        if unassigned:
            logger.warning(
                f"Unassigned programs due to resource/device constraints: {', '.join(unassigned)}"
            )

        # Get the solution fingerprint
        fingerprint = str(hash(json.dumps(assignment)))
        logger.info(f"Solution fingerprint: {fingerprint}")
        logger.info(f"Computed assignment: {assignment}")

        return assignment, fingerprint
    else:
        logger.error(f"Scheduling failed. Status: {solver.StatusName(status)}")
        for m in machines:
            logger.info(
                f"Machine {m.id}: CPU={m.cpu_cores}, RAM={m.ram_gb}, VRAM={m.vram_gb}, Devices={m.devices}"
            )
        for p in programs:
            logger.info(
                f"Program {p.name}: CPU={p.cpu_cores}, RAM={p.ram_gb}, VRAM={p.vram_gb}, Devices={p.required_devices}, RunOnAll={p.run_on_all_machines}"
            )
        return {}, ""


def broadcast(message: Any):
    """Broadcast message to all other machines (UDP)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    for machine in MACHINES.values():
        if machine.id != LOCAL_ID:
            try:
                sock.sendto(json.dumps(asdict(message)).encode(), (machine.ip, 5000))
            except Exception as e:
                logger.error(f"Failed to send to {machine.id}: {e}")
    sock.close()


def receive_messages():
    """Receive messages from other machines."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 5000))
    while True:
        data, _ = sock.recvfrom(4096)
        try:
            message_dict = json.loads(data.decode())
            handle_message(message_dict)
        except Exception as e:
            logger.error(f"Error processing message: {e}")
        time.sleep(0)  # thread switch


def handle_message(message: Dict[str, Any]):
    """Handle incoming messages."""
    global current_schedule, schedule_fingerprints
    msg_type = message.get("type")

    if msg_type == "schedule_hash":
        with schedule_agreement_lock:
            sender = message["sender"]
            fingerprint = message["fingerprint"]
            assignment = message["assignment"]

            logger.info(f"Received schedule from {sender}: fingerprint={fingerprint}")
            logger.debug(f"Received assignment from {sender}: {assignment}")

            schedule_fingerprints[sender] = {
                "fingerprint": fingerprint,
                "assignment": assignment,
                "timestamp": time.time()
            }

            # Check if we have responses from all expected machines
            expected_machines = set(m.id for m in MACHINES.values() if m.id != LOCAL_ID)
            received_machines = set(schedule_fingerprints.keys())

            if expected_machines.issubset(received_machines):
                logger.info("Received schedule responses from all machines")
                schedule_agreement_event.set()

    elif msg_type == "heartbeat":
        heartbeats[message["id"]] = time.time()
        # Reintegrate machine if it was previously removed
        if message["id"] not in resource_view and message["id"] in MACHINES and current_schedule is not None:
            resource_view[message["id"]] = MACHINES[message["id"]]
            logger.info(f"Reintegrated machine {message['id']} into resource_view")
            current_schedule = None
            schedule_computer()

    elif msg_type == "startup_ping":
        pong_msg = StartupPongMessage(type="startup_pong", id=LOCAL_ID)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sender_ip = next(m.ip for m in MACHINES.values() if m.id == message["id"])
            sock.sendto(json.dumps(asdict(pong_msg)).encode(), (sender_ip, 5000))
            sock.close()
        except Exception as e:
            logger.error(f"Failed to send pong to {message['id']}: {e}")

    elif msg_type == "startup_pong":
        startup_responses[message["id"]] = time.time()


def run_program(program_path: str) -> subprocess.Popen:
    """Run a program using subprocess."""
    try:
        return subprocess.Popen(["python3", program_path])
    except Exception as e:
        logger.error(f"Failed to run {program_path}: {e}")
        return None


def stop_program(proc: subprocess.Popen):
    """Stop a running program."""
    if proc:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def wait_for_all_machines():
    """Wait for all machines to be online before proceeding."""
    global startup_responses, MACHINES
    startup_responses = {}

    logger.info("Waiting for all machines to come online...")
    logger.info(f"Expected machines: {list(MACHINES.keys())}")

    start_time = time.time()
    timeout = 60

    while time.time() - start_time < timeout:
        ping_msg = StartupPingMessage(type="startup_ping", id=LOCAL_ID)
        broadcast(ping_msg)
        expected_machines = set(m.id for m in MACHINES.values() if m.id != LOCAL_ID)
        responding_machines = set(startup_responses.keys())
        if expected_machines.issubset(responding_machines):
            logger.info("All machines are online! Proceeding with orchestration.")
            return True
        missing_machines = expected_machines - responding_machines
        logger.info(f"Still waiting for machines: {list(missing_machines)}")
        time.sleep(1)
    responding_machines = set(startup_responses.keys())
    expected_machines = set(m.id for m in MACHINES.values() if m.id != LOCAL_ID)
    missing_machines = expected_machines - responding_machines
    if missing_machines:
        logger.warning(f"Timeout reached. Missing machines: {list(missing_machines)}")
        logger.warning("Proceeding with available machines only.")
        available_machine_ids = responding_machines | {LOCAL_ID}
        MACHINES = {k: v for k, v in MACHINES.items() if k in available_machine_ids}
        logger.info(f"Updated machine list: {list(MACHINES.keys())}")
    return True


#def resource_monitor():
#    """Periodically share local resources."""
#    while True:
#        if orchestration_started:
#            resources = get_local_resources()
#            broadcast(
#                ResourceMessage(
#                    type="resource",
#                    id=resources.id,
#                    ip=resources.ip,
#                    cpu_cores=resources.cpu_cores,
#                    cpu_ghz=resources.cpu_ghz,
#                    ram_gb=resources.ram_gb,
#                    vram_gb=resources.vram_gb,
#                    gpus=[asdict(gpu) for gpu in resources.gpus],
#                    devices=resources.devices,
#                    network=asdict(resources.network),
#                )
#            )
#        time.sleep(0.2)


def schedule_computer():
    """Compute and agree on schedule once at startup."""
    global current_schedule, schedule_fingerprints

    if not resource_view:
        logger.error("No machines available for scheduling")
        return

    logger.info("Starting schedule computation...")
    logger.info(f"Available machines: {list(resource_view.keys())}")

    # Compute schedule locally
    assignment, fingerprint = compute_schedule(list(resource_view.values()), PROGRAMS)

    if not assignment or not fingerprint:
        logger.error("Failed to compute schedule")
        return

    # Reset agreement tracking
    with schedule_agreement_lock:
        schedule_fingerprints.clear()
        schedule_agreement_event.clear()

    # Broadcast our schedule
    logger.info(f"Broadcasting schedule: fingerprint={fingerprint}")
    broadcast(
        ScheduleHashMessage(
            type="schedule_hash",
            sender=LOCAL_ID,
            fingerprint=fingerprint,
            assignment=assignment
        )
    )

    # Wait for responses from all machines (with timeout)
    logger.info("Waiting for schedule responses from other machines...")
    agreement_reached = schedule_agreement_event.wait(timeout=10.0)

    if not agreement_reached:
        logger.error("Timeout waiting for schedule responses")
        return

    # Analyze responses
    with schedule_agreement_lock:
        logger.info("Analyzing schedule agreement...")

        # Count fingerprints (including our own)
        fingerprint_counts = defaultdict(int)
        fingerprint_counts[fingerprint] += 1  # Count our own

        assignments_by_fingerprint = defaultdict(list)
        assignments_by_fingerprint[fingerprint].append(f"{LOCAL_ID}(local)")

        for sender, data in schedule_fingerprints.items():
            fp = data["fingerprint"]
            fingerprint_counts[fp] += 1
            assignments_by_fingerprint[fp].append(sender)

        logger.info(f"Fingerprint counts: {dict(fingerprint_counts)}")

        # Find majority
        total_machines = len(MACHINES)
        majority_threshold = total_machines // 2 + 1

        majority_fingerprint = None
        for fp, count in fingerprint_counts.items():
            logger.info(f"Fingerprint {fp}: {count}/{total_machines} machines")
            if count >= majority_threshold:
                majority_fingerprint = fp
                break

        if majority_fingerprint == fingerprint:
            logger.info(f"✓ Schedule agreement reached! Fingerprint: {majority_fingerprint}")
            logger.info(f"  Agreeing machines: {assignments_by_fingerprint[majority_fingerprint]}")
            current_schedule = assignment
            logger.info(f"  Final schedule: {assignment}")
        else:
            logger.error("✗ No majority agreement on schedule")
            if majority_fingerprint:
                logger.error(f"  Majority fingerprint: {majority_fingerprint}")
                logger.error(f"  Our fingerprint: {fingerprint}")
                logger.error(f"  Majority machines: {assignments_by_fingerprint[majority_fingerprint]}")
            else:
                logger.error("  No fingerprint achieved majority")

            # Debug: Show all assignments
            logger.error("  All received assignments:")
            logger.error(f"    {LOCAL_ID}(local): {assignment}")
            for sender, data in schedule_fingerprints.items():
                logger.error(f"    {sender}: {data['assignment']}")

        # Clear fingerprints for next round
        schedule_fingerprints.clear()


def program_manager():
    """Manage running programs, monitor crashes/exits."""
    global running_programs
    while True:
        if orchestration_started and current_schedule:
            for prog_name, proc in list(running_programs.items()):
                if proc and proc.poll() is not None:
                    return_code = proc.return_code
                    logger.info(f"Program {prog_name} exited with code {return_code}")
                    if (
                        prog_name in current_schedule
                        and current_schedule[prog_name] == LOCAL_ID
                    ):
                        if return_code == 0:
                            logger.info(f"Program {prog_name} ended naturally")
                        else:
                            logger.warning(
                                f"Program {prog_name} crashed with code {return_code}, restarting"
                            )
                            prog = next(
                                (
                                    p
                                    for p in PROGRAMS
                                    if p.name == prog_name.split("_")[0]
                                ),
                                None,
                            )
                            if prog:
                                proc = run_program(prog.path)
                                if proc:
                                    running_programs[prog_name] = proc
                    else:
                        stop_program(proc)
                        del running_programs[prog_name]
            for prog in PROGRAMS:
                if prog.run_on_all_machines:
                    prog_key = f"{prog.name}_{LOCAL_ID}"
                    if (
                        current_schedule.get(prog_key) == LOCAL_ID
                        and prog_key not in running_programs
                    ):
                        proc = run_program(prog.path)
                        if proc:
                            running_programs[prog_key] = proc
                            logger.info(f"Started program {prog_key}")
                else:
                    if (
                        current_schedule.get(prog.name) == LOCAL_ID
                        and prog.name not in running_programs
                    ):
                        proc = run_program(prog.path)
                        if proc:
                            running_programs[prog.name] = proc
                            logger.info(f"Started program {prog.name}")
        time.sleep(0.2)


def heartbeat_sender():
    """Send rapid heartbeats."""
    while True:
        if orchestration_started:
            broadcast(HeartbeatMessage(type="heartbeat", id=LOCAL_ID))
        time.sleep(0.2)


def heartbeat_monitor():
    """Monitor heartbeats and detect failures."""
    while True:
        if orchestration_started:
            current_time = time.time()
            for machine_id, last_beat in list(heartbeats.items()):
                if current_time - last_beat > 2.0:  # 10 missed heartbeats
                    logger.warning(f"Machine {machine_id} failed")
                    resource_view.pop(machine_id, None)
                    heartbeats.pop(machine_id, None)
                    global current_schedule
                    current_schedule = None
                    schedule_computer()
        time.sleep(0.2)


def main():
    """Main function to start all threads."""
    global orchestration_started, resource_view, heartbeats
    threading.Thread(target=receive_messages, daemon=True).start()
    wait_for_all_machines()
    resource_view = {m.id: m for m in MACHINES.values()}
    heartbeats = {m.id: time.time() for m in MACHINES.values() if m.id!=LOCAL_ID}
    #threading.Thread(target=resource_monitor, daemon=True).start()
    threading.Thread(target=program_manager, daemon=True).start()
    threading.Thread(target=heartbeat_sender, daemon=True).start()
    threading.Thread(target=heartbeat_monitor, daemon=True).start()
    orchestration_started = True
    schedule_computer()
    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
