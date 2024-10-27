import smtplib
from base64 import b64decode
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
import json
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.protocols.gmpv208 import ReportFormatType
from gvm.transforms import EtreeTransform
from datetime import datetime
import time

# Login and connection data
email = #to_be_filled
password = #to_be_filled
connection = UnixSocketConnection(path='/bso/gvm/gvmd/gvmd.sock')
transform = EtreeTransform()

state_file = 'scan_state.json'  # File to store scan state information


def load_state():
    # Load the scan state from a JSON file
    try:
        with open(state_file, 'r') as f:
            state = json.load(f)
            if 'tasks' not in state:
                state['tasks'] = []
            return state
    except FileNotFoundError:
        return {}  # Return an empty state if file does not exist


def save_state(state):
    # Save the scan state to a JSON file
    with open(state_file, 'w') as f:
        json.dump(state, f)


def monitor_reports():
    # Monitor reports for tasks to check for completion status
    with Gmp(connection, transform=transform) as gmp:
        gmp.authenticate('admin', 'admin')  # Authenticate with GVM
        while True:
            state = load_state()  # Load current scan state
            for task_info in state.get('tasks', []):
                task_id = task_info.get('task_id')
                last_status = task_info.get('last_status')
                task = gmp.get_task(task_id)
                scan_name = task_info.get('scan_name')
                current_status = task.find(".//status").text
                print(scan_name + ' ' + current_status)
                
                # If the task is completed and the status has changed
                if current_status == 'Done' and current_status != last_status:
                    report_name = task_info['report_name']
                    try:
                        # Generate and email the report
                        get_report(gmp, task_id, report_name)
                        send_email_report(receiver=task_info.get('receiver_email'), report_name=report_name)
                    except Exception as e:
                        print(f"Error processing task {task_id}: {e}")
                
                # Update the task's last status in the state
                task_info['last_status'] = current_status
                save_state(state)
            time.sleep(30)  # Wait 30 seconds before checking again


def get_report(gmp, task_id, report_name):
    # Generate the report for a given task
    ready_task = gmp.get_task(task_id)
    report_id = ready_task.find(".//task").find('.//report').attrib.get("id")
    report = gmp.get_report(report_id=report_id, details=True, report_format_id=ReportFormatType.PDF,
                            filter_string="apply_overrides=0 levels=hmlg rows=100 min_qod=70 first=1 sort-reverse=severity")
    report_element = report.find("report")
    content = report_element.find("report_format").tail
    binary_base64_encoded_pdf = content.encode('ascii')
    binary_pdf = b64decode(binary_base64_encoded_pdf)
    pdf_path = Path(f'{report_name}.pdf').expanduser()
    pdf_path.write_bytes(binary_pdf)
    print(f"PDF report '{report_name}' has been created")


def send_email_report(receiver, report_name):
    # Send the report via email
    server = smtplib.SMTP('smtp server', 587)
    server.starttls()
    server.login(email, password)
    msg = MIMEMultipart()
    msg['From'] = email
    msg['To'] = receiver
    msg['Subject'] = f'Report: {report_name}'
    body = "Scan report"
    msg.attach(MIMEText(body, 'plain'))
    file = f"{report_name}.pdf"
    
    # Attach the PDF report
    with open(file, "rb") as attachment:
        part = MIMEApplication(attachment.read(), _subtype="pdf")
        part.add_header('Content-Disposition', 'attachment', filename=file)
        msg.attach(part)
    
    server.sendmail(email, receiver, msg.as_string())
    server.quit()
    print(f"Email with report '{report_name}' was sent successfully.")


def main():
    # Main function to start report monitoring
    monitor_reports()


if __name__ == "__main__":
    main()