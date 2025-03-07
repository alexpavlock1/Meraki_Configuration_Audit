import os
import json
import uuid
import logging
import tempfile
import asyncio
import datetime
import smtplib
import requests  # Add this import
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.executors.pool import ThreadPoolExecutor

# Configure the scheduler
scheduler = BackgroundScheduler(
    jobstores={
        'default': SQLAlchemyJobStore(url='sqlite:///scheduler.sqlite')
    },
    executors={
        'default': ThreadPoolExecutor(max_workers=5)
    },
    job_defaults={
        'coalesce': False,
        'max_instances': 3
    }
)

# Start the scheduler when the module is imported
scheduler.start()

def save_schedule(schedule_data):
    """Save a scheduled report to the database."""
    # Create schedules directory if it doesn't exist
    os.makedirs('schedules', exist_ok=True)
    
    # Generate a unique ID for this schedule
    schedule_id = str(uuid.uuid4())
    
    # Create a schedule file
    schedule_file = os.path.join('schedules', f'{schedule_id}.json')
    with open(schedule_file, 'w') as file:
        json.dump(schedule_data, file, indent=4)
    
    # Add the job to the scheduler
    setup_scheduled_job(schedule_id, schedule_data)
    
    logging.debug(f"Saved schedule to {schedule_file}")
    return schedule_id

def setup_scheduled_job(schedule_id, schedule_data):
    """Set up a scheduled job with APScheduler."""
    frequency = schedule_data['frequency']
    time_str = schedule_data.get('time', '00:00')
    hour, minute = map(int, time_str.split(':'))
    
    # Determine when this job should run
    if frequency == 'weekly':
        # Run weekly on the specified day of week
        day_of_week = int(schedule_data['day_of_week'])
        trigger = 'cron'
        trigger_args = {
            'day_of_week': day_of_week,
            'hour': hour,
            'minute': minute
        }
    elif frequency == 'biweekly':
        # Run every other week on the specified day of week
        day_of_week = int(schedule_data['day_of_week'])
        trigger = 'cron'
        trigger_args = {
            'day_of_week': day_of_week,
            'hour': hour,
            'minute': minute,
            'week': '*/2'  # Run every 2 weeks
        }
    elif frequency == 'monthly':
        # Run monthly on the specified day of month
        day_of_month = int(schedule_data['day_of_month'])
        trigger = 'cron'
        trigger_args = {
            'day': day_of_month,
            'hour': hour,
            'minute': minute
        }
    
    # Add the job to the scheduler
    scheduler.add_job(
        run_scheduled_report,
        trigger=trigger,
        **trigger_args,
        id=schedule_id,
        replace_existing=True,
        args=[schedule_id, schedule_data]
    )
    
    logging.debug(f"Scheduled job {schedule_id} with trigger {trigger} and args {trigger_args}")

def run_scheduled_report(schedule_id, schedule_data):
    """Run a scheduled report and email the results."""
    logging.debug(f"Running scheduled report {schedule_id}")
    
    try:
        # Re-create the session data from the schedule data
        api_key = schedule_data['api_key']
        orgs = schedule_data['orgs']
        mx_checks = schedule_data['mx_checks']
        ms_checks = schedule_data['ms_checks']
        mr_checks = schedule_data['mr_checks']
        golden_images = schedule_data['golden_images']
        compliance_networks = schedule_data['compliance_networks']
        template_ids = schedule_data.get('template_ids', [])
        
        # Other settings
        l3_firewall_source_octet = int(schedule_data.get('l3_firewall_source_octet', 4))
        l3_firewall_destination_octet = int(schedule_data.get('l3_firewall_destination_octet', 4))
        cellular_firewall_source_octet = int(schedule_data.get('cellular_firewall_source_octet', 4))
        cellular_firewall_destination_octet = int(schedule_data.get('cellular_firewall_destination_octet', 4))
        one_to_many_nat_lan_ip_octet = int(schedule_data.get('one_to_many_nat_lan_ip_octet', 4))
        one_to_one_nat_lan_ip_octet = int(schedule_data.get('one_to_one_nat_lan_ip_octet', 4))
        inbound_firewall_source_octet = int(schedule_data.get('inbound_firewall_source_octet', 4))
        inbound_firewall_destination_octet = int(schedule_data.get('inbound_firewall_destination_octet', 4))
        port_forwarding_lan_ip_octet = int(schedule_data.get('port_forwarding_lan_ip_octet', 4))
        vlans_subnet_octet = int(schedule_data.get('vlans_subnet_octet', 4))
        
        # Create a temporary directory for report files
        with tempfile.TemporaryDirectory() as temp_dir:
            report_directory = os.path.join(temp_dir, 'report_files')
            os.makedirs(report_directory, exist_ok=True)
            
            # Run the data gathering and compliance check
            from gatherinfo import run_gatherinfo
            run_gatherinfo(
                api_key=api_key,
                orgs=orgs,
                mx_checks=mx_checks,
                ms_checks=ms_checks,
                mr_checks=mr_checks,
                golden_images=golden_images,
                compliance_networks=compliance_networks,
                l3_firewall_source_octet=l3_firewall_source_octet,
                l3_firewall_destination_octet=l3_firewall_destination_octet,
                cellular_firewall_source_octet=cellular_firewall_source_octet,
                cellular_firewall_destination_octet=cellular_firewall_destination_octet,
                one_to_many_nat_lan_ip_octet=one_to_many_nat_lan_ip_octet,
                one_to_one_nat_lan_ip_octet=one_to_one_nat_lan_ip_octet,
                inbound_firewall_source_octet=inbound_firewall_source_octet,
                inbound_firewall_destination_octet=inbound_firewall_destination_octet,
                port_forwarding_lan_ip_octet=port_forwarding_lan_ip_octet,
                vlans_subnet_octet=vlans_subnet_octet,
                template_ids=template_ids
            )
            
            from compliance_check import run_compliance_check
            run_compliance_check()
            
            from report_generation import generate_report, zip_files
            asyncio.run(generate_report(report_directory))
            
            # Create zip file for email attachment
            zip_filename = os.path.join(temp_dir, 'compliance_report.zip')
            zip_files(report_directory, zip_filename)
            
            # Send email with the report
            send_report_email(schedule_data['email'], zip_filename)
    
    except Exception as e:
        logging.error(f"Error running scheduled report {schedule_id}: {e}")
        # Send error notification email
        send_error_email(schedule_data['email'], str(e))

def send_report_email(recipient_email, report_zip_path):
    """Send an email with the compliance report attached using Mailgun."""
    try:
        # Mailgun API credentials
        mailgun_api_key = os.getenv('MAILGUN_API_KEY', '')
        mailgun_domain = os.getenv('MAILGUN_DOMAIN', '')
        sender_email = os.getenv('SENDER_EMAIL', '' + mailgun_domain)
        
        # API endpoint
        url = f"https://api.mailgun.net/v3/{mailgun_domain}/messages"
        
        # Create the email content
        subject = f'Meraki Compliance Report - {datetime.datetime.now().strftime("%Y-%m-%d")}'
        body = "Please find attached your Meraki Configuration Compliance Report.\n\n"
        
        # Prepare the multipart form data
        files = [("attachment", ("compliance_report.zip", open(report_zip_path, "rb").read()))]
        
        # Make the API request
        response = requests.post(
            url,
            auth=("api", mailgun_api_key),
            data={
                "from": sender_email,
                "to": recipient_email,
                "subject": subject,
                "text": body
            },
            files=files
        )
        
        # Check response
        response.raise_for_status()
        logging.debug(f"Sent compliance report email to {recipient_email}")
        return True
        
    except Exception as e:
        logging.error(f"Error sending email: {e}")
        return False

def send_error_email(recipient_email, error_message):
    """Send an email notification about an error in report generation."""
    try:
        # Mailgun API credentials
        mailgun_api_key = os.getenv('MAILGUN_API_KEY', '')
        mailgun_domain = os.getenv('MAILGUN_DOMAIN', '')
        sender_email = os.getenv('SENDER_EMAIL', '' + mailgun_domain)
        
        # API endpoint
        url = f"https://api.mailgun.net/v3/{mailgun_domain}/messages"
        
        # Create the email content
        subject = f'ERROR: Meraki Compliance Report - {datetime.datetime.now().strftime("%Y-%m-%d")}'
        body = f"An error occurred while generating your scheduled Meraki Configuration Compliance Report.\n\n"
        body += f"Error details: {error_message}\n\n"
        body += "Please check the application logs for more information or try running the report manually."
        
        # Make the API request
        response = requests.post(
            url,
            auth=("api", mailgun_api_key),
            data={
                "from": sender_email,
                "to": recipient_email,
                "subject": subject,
                "text": body
            }
        )
        
        # Check response
        response.raise_for_status()
        logging.debug(f"Sent error notification email to {recipient_email}")
        return True
        
    except Exception as e:
        logging.error(f"Error sending error notification email: {e}")
        return False

def load_existing_schedules():
    """Load existing schedules from the schedules directory."""
    schedules_dir = 'schedules'
    if os.path.exists(schedules_dir):
        for filename in os.listdir(schedules_dir):
            if filename.endswith('.json'):
                try:
                    schedule_id = filename.replace('.json', '')
                    with open(os.path.join(schedules_dir, filename), 'r') as file:
                        schedule_data = json.load(file)
                    setup_scheduled_job(schedule_id, schedule_data)
                    logging.info(f"Loaded schedule {schedule_id}")
                except Exception as e:
                    logging.error(f"Error loading schedule {filename}: {e}")