import json
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from datetime import datetime, timedelta
import pytz
from icalendar import Calendar, Event
from icalendar import vRecur
import nmap

# Connection details
connection = UnixSocketConnection(path='/bso/gvm/gvmd/gvmd.sock')
transform = EtreeTransform()

state_file = 'scan_state.json'


def save_state(state):
    """Save the current state to a JSON file."""
    with open(state_file, 'w') as f:
        json.dump(state, f)


def load_state():
    """Load the state from a JSON file."""
    try:
        with open(state_file, 'r') as f:
            state = json.load(f)
            if 'tasks' not in state:
                state['tasks'] = []
            return state
    except FileNotFoundError:
        return {}


def create_target(gmp, ip_list, target_name):
    """Create a new target for the scan."""
    port_list_TEST = '33d0cd82-57c6-11e1-8ed1-406186ea4fc5'  # Test port list
    port_list_id = '4a4717fe-57d2-11e1-9a26-406186ea4fc5'  # All IANA assigned TCP and UDP
    target = gmp.create_target(name=target_name, hosts=ip_list, port_list_id=port_list_TEST)
    target_id = target.attrib.get('id')
    return target_id


def create_scan(gmp, target_id, schedule_id, scan_name):
    """Create a new scan task."""
    config_id_TEST = '8715c877-47a0-438d-98a3-27c7a6ab2196'  # Test config
    config_id = 'daba56c8-73ec-11df-a475-002264764cea'  # Full and fast config
    scanner_id = '08b69003-5fc2-4037-a479-93b440211c73'  # Scanner ID
    task = gmp.create_task(name=scan_name, config_id=config_id_TEST, target_id=target_id, scanner_id=scanner_id,
                           schedule_id=schedule_id)
    task_id = task.attrib.get('id')
    return task_id


def display_scans():
    """Display existing scan tasks."""
    task_list = load_state()
    task_list = task_list['tasks']
    print("List of tasks:")
    for idx, task in enumerate(task_list):
        print(f"{idx + 1} Scan Name: {task['scan_name']} (ID: {task['task_id']}) Frequency: {task['freq']} Scanned IP: {task['ip']} Email for report: {task.get('receiver_email')}")


def create_schedule(gmp, freq, schedule_name):
    """Create a new schedule for the scan."""
    poland_tz = pytz.timezone('Europe/Warsaw')
    start_time = datetime.now() + timedelta(minutes=5)
    start_time = start_time.astimezone(poland_tz)
    cal = Calendar()
    cal.add('prodid', '-//Foo Bar//')
    cal.add('version', '2.0')
    event = Event()
    event.add('dtstamp', datetime.now(tz=pytz.UTC))
    event.add('dtstart', start_time)
    rrule = vRecur(freq=freq)
    event.add('rrule', rrule)
    cal.add_component(event)
    schedule = gmp.create_schedule(
        name=schedule_name,
        icalendar=cal.to_ical(),
        timezone="Europe/Warsaw"
    )
    schedule_id = schedule.attrib.get("id")
    return schedule_id


def create_new_scan():
    """Create a new scan based on user input."""
    option = input("Select 1 if you want to enter the IP address manually, 2 if you want to select from hosts on the network: ")
    if int(option) == 1:
        target_ip = input("Enter target IP addresses: ").split()
    elif int(option) == 2:
        net_ip = input("Enter network IP address: ")
        target_ip = find_host_in_network(net_ip)
    freq = input("Enter scan frequency (HOURLY, DAILY, WEEKLY, MONTHLY, YEARLY): ")
    receiver_email = input("Enter email address for sending reports: ")
    scan_name = input("Enter scan name: ")
    report_name = f"{scan_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    state = load_state()

    with Gmp(connection, transform=transform) as gmp:
        gmp.authenticate('admin', 'admin')  # Authenticate with the GMP
        target_id = create_target(gmp, target_ip, scan_name)
        schedule_id = create_schedule(gmp, freq, schedule_name=f'{scan_name}_{freq}')
        task_id = create_scan(gmp, target_id, schedule_id, scan_name)

        if 'tasks' not in state:
            state['tasks'] = []
        state['tasks'].append({'task_id': task_id, 'report_name': report_name, 'ip': target_ip, 'scan_name': scan_name, 'freq': freq, 'receiver_email': receiver_email})
        save_state(state)


def delete_scan():
    """Delete an existing scan task."""
    state = load_state()
    if 'tasks' not in state or not state['tasks']:
        print("No tasks to delete.")
        return

    task_list = state['tasks']
    print("List of tasks:")
    for idx, task in enumerate(task_list):
        print(f"{idx + 1}. {task['report_name']} (ID: {task['task_id']})")

    task_idx = int(input("Enter the number of the task to delete: ")) - 1
    if task_idx < 0 or task_idx >= len(task_list):
        print("Invalid task number.")
        return

    task_to_delete = task_list[task_idx]
    with Gmp(connection, transform=transform) as gmp:
        gmp.authenticate('admin', 'admin')
        gmp.delete_task(task_id=task_to_delete['task_id'])

    del task_list[task_idx]
    save_state(state)
    print("Task has been deleted.")


def find_host_in_network(network_address):
    """Scan the network to find active hosts."""
    nm = nmap.PortScanner()
    print(f"Searching for hosts in the network {network_address}. This may take a while.")
    nm.scan(hosts=network_address, arguments='-sn', sudo=True)  # Perform a ping scan
    active_hosts = [nm[host] for host in nm.all_hosts() if nm[host].hostname() != ""]
    print(f"Hosts detected in the network {network_address}:")
    for idx, host in enumerate(active_hosts):
        print(f"{idx + 1}. {host['hostnames'][0]['name']} {host['addresses']['ipv4']}")
    chosen_host_index = [int(x) - 1 for x in input("Enter the indices of the hosts you want to scan: ").split()]
    chosen_ip = [active_hosts[i]['addresses']['ipv4'] for i in chosen_host_index]
    return chosen_ip


def main():
    """Main loop for the application."""
    while True:
        print("\nMenu:")
        print("1. Create a new scan")
        print("2. Delete an existing scan")
        print("3. Display existing scans")
        print("4. Exit")
        choice = input("Select an option: ")

        if choice == '1':
            create_new_scan()
        elif choice == '2':
            delete_scan()
        elif choice == '3':
            display_scans()
        elif choice == '4':
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()