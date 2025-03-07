from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash, jsonify, send_from_directory, after_this_request
import json
import logging
import threading
import os
import shutil
import asyncio
import meraki.aio
import tempfile
import uuid
import atexit
from scheduling import scheduler, load_existing_schedules, save_schedule
from report_generation import zip_files

app = Flask(__name__)
app.secret_key = 'your_secret_key'
flash_message = None

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

report_status = {"status": "idle"}
def shutdown_scheduler():
    if scheduler.running:
        scheduler.shutdown()

atexit.register(shutdown_scheduler)
def clear_old_data():
    if os.path.exists('session_data.json'):
        os.remove('session_data.json')
    if os.path.exists('report_files'):
        shutil.rmtree('report_files')
    if os.path.exists('compliance_report.zip'):
        os.remove('compliance_report.zip')
    # More aggressive cleanup of org directories
    for root, dirs, files in os.walk('.'):
        for dir in dirs:
            if dir.startswith('Org_'):
                shutil.rmtree(os.path.join(root, dir))
    logging.debug("Cleared old data files and directories")

def clear_intermediate_files():
    # List of files that should be cleared before generating a new report
    text_files = [
        'summary_table.txt',
        'non_compliant_networks_table.txt',
        'verdict_table.txt',
        'network_verdict_table.txt',
        'anomalies.json'
    ]

    # Remove each specified file if it exists
    for file in text_files:
        if os.path.exists(file):
            os.remove(file)
            logging.debug(f"Cleared file: {file}")

    # Optionally clear directories or other files specific to your use case
    if os.path.exists('report_files'):
        shutil.rmtree('report_files')
        logging.debug("Cleared report files directory")

    # Clear other directories or files if necessary
    if os.path.exists('session_data.json'):
        os.remove('session_data.json')
        logging.debug("Cleared session data file")

@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')

@app.route('/set_api_key', methods=['POST'])
def set_api_key():
    api_key = request.form['api_key']
    session['api_key'] = api_key
    logging.debug(f"API key set in session: {api_key}")
    return redirect(url_for('orgs'))


@app.route('/orgs', methods=['GET', 'POST'])
async def orgs():
    if 'api_key' not in session:
        return redirect(url_for('logout'))
    
    if request.method == 'POST':
        selected_orgs = request.form.getlist('orgs[]')
        session['selected_orgs'] = selected_orgs
        logging.debug(f"Selected orgs set in session: {selected_orgs}")
        return redirect(url_for('compliance_checks'))
    
    api_key = session['api_key']
    # Initialize Meraki dashboard API session
    async with meraki.aio.AsyncDashboardAPI(api_key, output_log=False) as dashboard:
        try:
            organizations = await dashboard.organizations.getOrganizations()
            session['organizations'] = organizations
            logging.debug(f"Organizations set in session: {organizations}")
        except Exception as e:
            logging.error(f"Error fetching organizations: {e}")
            return redirect(url_for('logout'))
    
    return render_template('orgs.html', organizations=organizations)

@app.route('/compliance_checks', methods=['GET', 'POST'])
def compliance_checks():
    if 'selected_orgs' not in session:
        return redirect(url_for('logout'))
    
    if request.method == 'POST':
        mx_checks = request.form.getlist('mx_checks[]')
        ms_checks = request.form.getlist('ms_checks[]')
        mr_checks = request.form.getlist('mr_checks[]')
        
        # Get the octet selections for L3, Cellular, One-to-Many NAT, One-to-One NAT, Inbound firewall rules, Port Forwarding rules, and VLANs
        l3_firewall_source_octet = request.form.get('l3_firewall_source_octet')
        l3_firewall_destination_octet = request.form.get('l3_firewall_destination_octet')
        cellular_firewall_source_octet = request.form.get('cellular_firewall_source_octet')
        cellular_firewall_destination_octet = request.form.get('cellular_firewall_destination_octet')
        one_to_many_nat_lan_ip_octet = request.form.get('one_to_many_nat_lan_ip_octet')
        one_to_one_nat_lan_ip_octet = request.form.get('one_to_one_nat_lan_ip_octet')
        inbound_firewall_source_octet = request.form.get('inbound_firewall_source_octet')
        inbound_firewall_destination_octet = request.form.get('inbound_firewall_destination_octet')
        port_forwarding_lan_ip_octet = request.form.get('port_forwarding_lan_ip_octet')
        vlans_subnet_octet = request.form.get('vlans_subnet_octet')
        
        session['mx_checks'] = mx_checks
        session['ms_checks'] = ms_checks
        session['mr_checks'] = mr_checks
        session['l3_firewall_source_octet'] = l3_firewall_source_octet
        session['l3_firewall_destination_octet'] = l3_firewall_destination_octet
        session['cellular_firewall_source_octet'] = cellular_firewall_source_octet
        session['cellular_firewall_destination_octet'] = cellular_firewall_destination_octet
        session['one_to_many_nat_lan_ip_octet'] = one_to_many_nat_lan_ip_octet
        session['one_to_one_nat_lan_ip_octet'] = one_to_one_nat_lan_ip_octet
        session['inbound_firewall_source_octet'] = inbound_firewall_source_octet
        session['inbound_firewall_destination_octet'] = inbound_firewall_destination_octet
        session['port_forwarding_lan_ip_octet'] = port_forwarding_lan_ip_octet
        session['vlans_subnet_octet'] = vlans_subnet_octet
        
        logging.debug(f"MX checks set in session: {mx_checks}")
        logging.debug(f"MS checks set in session: {ms_checks}")
        logging.debug(f"MR checks set in session: {mr_checks}")
        logging.debug(f"L3 Firewall Source Octet: {l3_firewall_source_octet}")
        logging.debug(f"L3 Firewall Destination Octet: {l3_firewall_destination_octet}")
        logging.debug(f"Cellular Firewall Source Octet: {cellular_firewall_source_octet}")
        logging.debug(f"Cellular Firewall Destination Octet: {cellular_firewall_destination_octet}")
        logging.debug(f"One-to-Many NAT LAN IP Octet: {one_to_many_nat_lan_ip_octet}")
        logging.debug(f"One-to-One NAT LAN IP Octet: {one_to_one_nat_lan_ip_octet}")
        logging.debug(f"Inbound Firewall Source Octet: {inbound_firewall_source_octet}")
        logging.debug(f"Inbound Firewall Destination Octet: {inbound_firewall_destination_octet}")
        logging.debug(f"Port Forwarding LAN IP Octet: {port_forwarding_lan_ip_octet}")
        logging.debug(f"VLANs Subnet Octet: {vlans_subnet_octet}")
        
        return redirect(url_for('select_networks'))
    
    return render_template('compliance_checks.html')

@app.route('/select_networks', methods=['GET', 'POST'])
async def select_networks():
    if 'selected_orgs' not in session:
        return redirect(url_for('logout'))
    
    if request.method == 'POST':
        golden_images = {}
        compliance_networks = {}
        
        for org_id in session['selected_orgs']:
            golden_images[org_id] = request.form.get(f'golden_image_{org_id}')
            compliance_networks[org_id] = request.form.getlist(f'compliance_networks_{org_id}')
        
        session['golden_images'] = golden_images
        session['compliance_networks'] = compliance_networks
        
        # Store which IDs are templates vs networks
        template_ids = request.form.getlist('template_ids')
        session['template_ids'] = template_ids
        
        logging.debug(f"Golden images set in session: {golden_images}")
        logging.debug(f"Compliance networks set in session: {compliance_networks}")
        logging.debug(f"Template IDs set in session: {template_ids}")
        
        return redirect(url_for('schedule_report'))
    
    api_key = session['api_key']
    async with meraki.aio.AsyncDashboardAPI(api_key, output_log=False) as dashboard:
        org_networks = {}
        org_templates = {}
        org_names = {}
        
        for org in session['organizations']:
            org_id = org['id']
            if org_id in session['selected_orgs']:
                org_name = org['name']
                org_names[org_id] = org_name
                
                # Get networks
                networks = await dashboard.organizations.getOrganizationNetworks(org_id)
                
                # Get templates
                try:
                    templates = await dashboard.organizations.getOrganizationConfigTemplates(org_id)
                    # Add a flag to identify templates in the selection UI
                    for template in templates:
                        template['isTemplate'] = True
                    org_templates[org_id] = templates
                except Exception as e:
                    logging.error(f"Error fetching templates for org {org_id}: {e}")
                    org_templates[org_id] = []
                
                org_networks[org_id] = networks
    
    return render_template('select_networks.html', 
                          org_networks=org_networks, 
                          org_templates=org_templates, 
                          org_names=org_names)
@app.route('/schedule_report', methods=['GET', 'POST'])
def schedule_report():
    if 'api_key' not in session:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        logging.debug(f"Form submitted with values: {request.form}")
        schedule_option = request.form.get('schedule_option')
        logging.debug(f"Schedule option selected: {schedule_option}")
        if schedule_option == 'run_now':
            # Redirect to generate report immediately
            return redirect(url_for('generate_report_route'))
        elif schedule_option == 'schedule':
            # Get scheduling information
            frequency = request.form.get('frequency')
            day_of_week = request.form.get('day_of_week')
            day_of_month = request.form.get('day_of_month')
            time = request.form.get('time')
            email = request.form.get('email')
            
            # Save scheduling information
            schedule_data = {
                'frequency': frequency,
                'day_of_week': day_of_week,
                'day_of_month': day_of_month,
                'time': time,
                'email': email,
                'api_key': session['api_key'],
                'orgs': session.get('selected_orgs', []),
                'mx_checks': session.get('mx_checks', []),
                'ms_checks': session.get('ms_checks', []),
                'mr_checks': session.get('mr_checks', []),
                'golden_images': session.get('golden_images', {}),
                'compliance_networks': session.get('compliance_networks', {}),
                'template_ids': session.get('template_ids', []),
                'l3_firewall_source_octet': session.get('l3_firewall_source_octet', '4'),
                'l3_firewall_destination_octet': session.get('l3_firewall_destination_octet', '4'),
                'cellular_firewall_source_octet': session.get('cellular_firewall_source_octet', '4'),
                'cellular_firewall_destination_octet': session.get('cellular_firewall_destination_octet', '4'),
                'one_to_many_nat_lan_ip_octet': session.get('one_to_many_nat_lan_ip_octet', '4'),
                'one_to_one_nat_lan_ip_octet': session.get('one_to_one_nat_lan_ip_octet', '4'),
                'inbound_firewall_source_octet': session.get('inbound_firewall_source_octet', '4'),
                'inbound_firewall_destination_octet': session.get('inbound_firewall_destination_octet', '4'),
                'port_forwarding_lan_ip_octet': session.get('port_forwarding_lan_ip_octet', '4'),
                'vlans_subnet_octet': session.get('vlans_subnet_octet', '4')
            }
            
            # Save schedule
            schedule_id = save_schedule(schedule_data)
            
            # Show confirmation page
            return render_template('schedule_confirmation.html', schedule_data=schedule_data)
    
    return render_template('schedule_report.html')

# Find your existing generate_report_route function and update it to:
@app.route('/generate_report')
def generate_report_route():
    if 'api_key' not in session:
        logging.error("API key not found in session")
        return redirect(url_for('index'))
    
    # Save session data for the report generation
    session_data = {
        'api_key': session['api_key'],
        'orgs': session.get('selected_orgs', []),
        'mx_checks': session.get('mx_checks', []),
        'ms_checks': session.get('ms_checks', []),
        'mr_checks': session.get('mr_checks', []),
        'golden_images': session.get('golden_images', {}),
        'compliance_networks': session.get('compliance_networks', {}),
        'template_ids': session.get('template_ids', []),  # Add template IDs
        'l3_firewall_source_octet': session.get('l3_firewall_source_octet', '4'),
        'l3_firewall_destination_octet': session.get('l3_firewall_destination_octet', '4'),
        'cellular_firewall_source_octet': session.get('cellular_firewall_source_octet', '4'),
        'cellular_firewall_destination_octet': session.get('cellular_firewall_destination_octet', '4'),
        'one_to_many_nat_lan_ip_octet': session.get('one_to_many_nat_lan_ip_octet', '4'),
        'one_to_one_nat_lan_ip_octet': session.get('one_to_one_nat_lan_ip_octet', '4'),
        'inbound_firewall_source_octet': session.get('inbound_firewall_source_octet', '4'),
        'inbound_firewall_destination_octet': session.get('inbound_firewall_destination_octet', '4'),
        'port_forwarding_lan_ip_octet': session.get('port_forwarding_lan_ip_octet', '4'),
        'vlans_subnet_octet': session.get('vlans_subnet_octet', '4')
    }
    
    with open('session_data.json', 'w') as file:
        json.dump(session_data, file)
    
    logging.debug(f"Session data saved to session_data.json: {session_data}")
    
    # Initialize report status
    global report_status
    report_status = {
        "status": "starting",
        "progress": 0,
        "message": "Initializing report generation..."
    }
    
    # Start the report generation in a background thread
    thread = threading.Thread(target=generate_report_thread, args=(session_data,))
    thread.daemon = True
    thread.start()
    
    # Redirect to the progress page
    return redirect(url_for('show_progress'))

# Add this new function for the report generation thread
def generate_report_thread(session_data):
    global report_status
    try:
        clear_old_data()  # Clear old data at the start
        
        with tempfile.TemporaryDirectory() as temp_dir:
            report_directory = os.path.join(temp_dir, 'report_files')
            os.makedirs(report_directory, exist_ok=True)

            # Data gathering phase
            report_status = {
                "status": "gathering_data",
                "progress": 25,
                "message": "Gathering network configuration data..."
            }
            
            from gatherinfo import run_gatherinfo
            run_gatherinfo(
                api_key=session_data['api_key'],
                orgs=session_data['orgs'],
                mx_checks=session_data['mx_checks'],
                ms_checks=session_data['ms_checks'],
                mr_checks=session_data['mr_checks'],
                golden_images=session_data['golden_images'],
                compliance_networks=session_data['compliance_networks'],
                l3_firewall_source_octet=int(session_data['l3_firewall_source_octet']),
                l3_firewall_destination_octet=int(session_data['l3_firewall_destination_octet']),
                cellular_firewall_source_octet=int(session_data['cellular_firewall_source_octet']),
                cellular_firewall_destination_octet=int(session_data['cellular_firewall_destination_octet']),
                one_to_many_nat_lan_ip_octet=int(session_data['one_to_many_nat_lan_ip_octet']),
                one_to_one_nat_lan_ip_octet=int(session_data['one_to_one_nat_lan_ip_octet']),
                inbound_firewall_source_octet=int(session_data['inbound_firewall_source_octet']),
                inbound_firewall_destination_octet=int(session_data['inbound_firewall_destination_octet']),
                port_forwarding_lan_ip_octet=int(session_data['port_forwarding_lan_ip_octet']),
                vlans_subnet_octet=int(session_data['vlans_subnet_octet']),
                template_ids=session_data.get('template_ids', [])
            )
            logging.debug("Gatherinfo completed")

            # Compliance check phase
            report_status = {
                "status": "checking_compliance",
                "progress": 50,
                "message": "Performing compliance checks..."
            }
            
            from compliance_check import run_compliance_check
            logging.debug("Starting compliance check")
            run_compliance_check()
            logging.debug("Compliance check completed")

            # Report generation phase
            report_status = {
                "status": "generating_report",
                "progress": 75,
                "message": "Generating final report..."
            }
            
            from report_generation import generate_report
            logging.debug("Starting report generation")
            asyncio.run(generate_report(report_directory))
            logging.debug("Report generation completed")
            
            # Creating zip file
            report_status = {
                "status": "creating_zip",
                "progress": 90,
                "message": "Creating downloadable package..."
            }
            
            zip_files(report_directory, 'compliance_report.zip')
            logging.debug("Zipped files into 'compliance_report.zip'")

        # Completed successfully
        report_status = {
            "status": "completed",
            "progress": 100,
            "message": "Report generation completed successfully."
        }
        logging.debug("Report generation process completed")
        
    except Exception as e:
        report_status = {
            "status": "failed",
            "progress": 0,
            "message": f"Report generation failed: {str(e)}"
        }
        logging.error(f"Report generation failed: {e}")

# Add a new route for the progress page
@app.route('/show_progress')
def show_progress():
    return render_template('progress.html')
    
@app.route('/download_report')
def download_report():
    zip_filename = 'compliance_report.zip'
    if os.path.exists(zip_filename):
        @after_this_request
        def cleanup(response):
            try:
                os.remove(zip_filename)
                clear_old_data()  # Make sure this gets called
                logging.debug("Cleared all data after download")
            except Exception as e:
                logging.error(f"Error cleaning up files: {e}")
            return response

        return send_file(zip_filename, as_attachment=True)
    else:
        logging.error(f"Zip file {zip_filename} does not exist")
        return redirect(url_for('index'))

@app.route('/check_report_status')
def check_report_status():
    return jsonify(report_status)

@app.route('/download_csv/<path:filename>')
def download_csv(filename):
    try:
        directory = os.path.dirname(filename)
        return send_from_directory(directory, os.path.basename(filename), as_attachment=True)
    except Exception as e:
        logging.error(f"Error sending CSV file: {e}")
        return redirect(url_for('index'))

@app.route('/download_all_csvs')
def download_all_csvs():
    try:
        zip_filename = "network_data_csvs.zip"
        with zipfile.ZipFile(zip_filename, 'w') as zipf:
            for root, dirs, files in os.walk("csv_files"):
                for file in files:
                    if file.endswith("_data.csv"):
                        zipf.write(os.path.join(root, file))
        return send_file(zip_filename, as_attachment=True)
    except Exception as e:
        logging.error(f"Error creating or sending ZIP file: {e}")
        return redirect(url_for('index'))



def create_app():
    with app.app_context():
        load_existing_schedules()
    return app

if __name__ == '__main__':
    create_app()
    app.run(debug=True)