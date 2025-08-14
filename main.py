################################################################################
#
#                           IR-TOOLBOX v1.0
#
# Description:    A streamlined incident reporting tool for Incident Responders
#                 following the K.I.S.S. principle.
#                
# Author:         Nicholas Thomason (171 CPT)
# Created:        2025
# License:        MIT License
#
# Purpose:        Standardized reporting for PIR, RFC, SPOT, SITREP, AAR, 
#                 and Vulnerability Assessment reports
#
# Dependencies:   textual, rich, reportlab, pathlib
# Repository:     https://github.com/[your-repo]
# Contact:        [your-contact]
#
#                        UNCLASSIFIED//FOR OFFICIAL USE ONLY
#
################################################################################


import textual, rich, os, json
from textual.app import App, ComposeResult, on
from textual.widgets import Header, Footer, Input, DataTable, Button, Label, Select, Static, Collapsible, TabbedContent, TabPane
from textual.screen import Screen, ModalScreen
from textual.containers import Vertical, Horizontal, ScrollableContainer, VerticalScroll, Grid
from datetime import datetime
import re
from pathlib import Path


#####
#
#	Launch this scrip via powershell, Execution Policy is needed on the system
#	Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
#####


incident_categories = """null
Other
Malware
Network-based
Access Control
Social Engineering
Web Application
Insider Threat
Physical Security
Supply Chain
Data Breach
Vulnerability Exploitation
Denial of Service
Incident in Cloud Services
Legal and Compliance""".splitlines()

confidence = """null
High
Medium
Low""".splitlines()

# PIR Artifact Types
artifact_types = """null
Command
Exploit
File
FQDN
IPv4
IPv6
Tool""".splitlines()

# RFC Status options
rfc_status = """null
Not Submitted
Submitted
Approved
In Progress
Completed
Rejected""".splitlines()

# RFC Severity options
rfc_severity = """null
Low
Medium
High
Critical""".splitlines()

# RFC Role options
rfc_role = """null
Domain Controller
Firewall
Server
Workstation
Router
Switch
Endpoint
UNK""".splitlines()

# CVSS Scores
cvss_scores = """null
0.0 - None
0.1-3.9 - Low
4.0-6.9 - Medium
7.0-8.9 - High
9.0-10.0 - Critical""".splitlines()

# Unit Size options
unit_sizes = """null
Individual
Team (2-4)
Squad (5-10)
Platoon (10-30)
Company (50-200)
Unknown""".splitlines()


SCRIPT_DIR = Path(__file__).parent.absolute()
REPORTS_DIR = SCRIPT_DIR / "files"


class FileContentModal(ModalScreen):
	"""Modal to display file contents"""
	
	def __init__(self, file_path: str, file_name: str):
		super().__init__()
		self.file_path = file_path
		self.file_name = file_name
		self.content = ""
		self.load_file_content()
	
	def load_file_content(self):
		"""Load the file content"""
		try:
			with open(self.file_path, 'r', encoding='utf-8') as f:
				self.content = f.read()
		except Exception as e:
			self.content = f"Error loading file: {e}"
	
	def compose(self) -> ComposeResult:
		with Vertical():
			yield Label(f"File: {self.file_name}", id="file_title")
			with ScrollableContainer():
				yield Static(self.content, id="file_content")
			with Horizontal():
				yield Button("Close", id="close_button", variant="primary")
	
	def on_button_pressed(self, event: Button.Pressed) -> None:
		if event.button.id == "close_button":
			self.dismiss()


class FileListModal(ModalScreen):
	"""Modal to display list of files with DataTable"""
	
	def __init__(self, report_type: str = ""):
		super().__init__()
		self.report_type = report_type
	
	def compose(self) -> ComposeResult:
		with Vertical():
			yield Label(f"Current {self.report_type} Reports", id="modal_title")
			yield DataTable(id="files_table")
			with Horizontal():
				yield Button("Refresh", id="refresh_button")
				yield Button("Close", id="close_modal_button", variant="primary")
	
	def on_mount(self) -> None:
		"""Initialize the table when modal opens"""
		self.populate_file_table()
	
	def populate_file_table(self):
		"""Populate the DataTable with files"""
		table = self.query_one("#files_table", DataTable)
		table.clear(columns=True)
		
		# Add columns
		table.add_column("Filename", width=50)
		table.add_column("Date Created", width=20)
		table.add_column("Size (KB)", width=15)
		
		# Get files from directory
		files = self.get_report_files()
		
		for file_info in files:
			table.add_row(
				file_info['display_name'],
				file_info['date_created'],
				file_info['size_kb']
			)
	
	def get_report_files(self):
		"""Get list of report files from directory"""
		files = []
		
		try:
			if not os.path.exists(REPORTS_DIR):
				return files
			
			# Get all .txt files
			txt_files = [f for f in os.listdir(REPORTS_DIR) if f.endswith('.txt')]
			
			# Filter by report type if specified
			if self.report_type:
				txt_files = [f for f in txt_files if self.report_type.upper() in f.upper()]
			
			# Process each file
			for filename in txt_files:
				file_path = os.path.join(REPORTS_DIR, filename)
				
				# Get file stats
				stat = os.stat(file_path)
				size_kb = round(stat.st_size / 1024, 1)
				date_created = datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M')
				
				# Remove extension for display
				display_name = filename.replace('.txt', '')
				
				files.append({
					'filename': filename,
					'display_name': display_name,
					'date_created': date_created,
					'size_kb': size_kb,
					'full_path': file_path
				})
			
			# Sort by filename (which should be chronological with new format)
			files.sort(key=lambda x: x['display_name'], reverse=True)
			
		except Exception as e:
			print(f"Error getting files: {e}")
		
		return files
	
	def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
		"""Handle double-click on table row"""
		# Get the filename from the selected row
		table = self.query_one("#files_table", DataTable)
		row_key = event.row_key
		
		# Get the display name from the table
		display_name = str(table.get_cell(row_key, "Filename"))
		
		# Find the full file path
		files = self.get_report_files()
		for file_info in files:
			if file_info['display_name'] == display_name:
				# Open file content modal
				self.app.push_screen(FileContentModal(file_info['full_path'], display_name))
				break
	
	def on_button_pressed(self, event: Button.Pressed) -> None:
		if event.button.id == "refresh_button":
			self.populate_file_table()
		elif event.button.id == "close_modal_button":
			self.dismiss()


class ReporterApp(App):
	CSS_PATH = "main.tcss"
	BINDINGS = [
		("d", "toggle_dark", "Dark Mode"),
		("escape", "app.exit(0)", "Back"),
		("ctrl+c", "quit", "Quit"),
	]

	def compose(self) -> ComposeResult:
		yield Header(show_clock=True)
		
		with TabbedContent(initial="pir_tab"):
			with TabPane("PIR Report", id="pir_tab"):
				yield from self.create_pir_content()
			
			with TabPane("RFC Report", id="rfc_tab"):
				yield from self.create_rfc_content()
			
			with TabPane("SPOT Report", id="spot_tab"):
				yield from self.create_spot_content()
			
			with TabPane("SITREP", id="sitrep_tab"):
				yield from self.create_sitrep_content()
			
			with TabPane("AAR", id="aar_tab"):
				yield from self.create_aar_content()
			
			with TabPane("Vulnerability Assessment", id="vuln_tab"):
				yield from self.create_vuln_content()
		
		yield Footer()

	def create_pir_content(self) -> ComposeResult:
		with Horizontal(id="PIRButtons"):
			yield Button("Create PIR Report", id="save_pir_button")
			yield Button("Clear PIR Form", id="clear_pir_button")
			yield Button("Current PIRs", id="get_current_pir_button")

		yield Label("PIR (Priority Intelligence Requirements) Report", id="pir_main_label")
		
		with Collapsible(id="pir_form", collapsed=False):
			yield Label("Timestamp and Enclave Making Report: ''YYYY-MM-DD HH:MM:SS UTC - ENCLAVE_NAME''")
			yield Input(placeholder="YYYY-MM-DD HH:MM:SS UTC - ENCLAVE_NAME", id="pir_timestamp_enclave")
			
			yield Label("PIR(s) Observed")
			yield Label("1.1 Who is conducting cyber attacks in the friendly operating environment?")
			yield Label("1.2 What TTPs are associated with observed malicious activities?")
			yield Label("1.3 What unique identifiers/signatures did malicious actors use?")
			yield Label("2.1 How did the actor gain initial access?")
			yield Label("2.2 How is the adversary implementing Command and Control?")
			yield Label("2.3 How has the adversary compromised the OT environment?")
			yield Label("2.3.2 What effects have been observed on the OT environment?")
			yield Label("3.1 How was malware deployed into the friendly environment?")
			yield Label("3.2 What methods of persistence (type and version) are present on ICS/SCADA systems?")
			yield Label("4.1 What friendly systems (IP, hostname, network, org, etc.) were targeted?")
			yield Label("4.1.1 How were friendly systems used for lateral movement?")
			yield Label("4.2 What are the effects of the attack?")
			yield Label("5.1 What foreign IO activity is associated with attacks on the network?")
			yield Input(placeholder="Just the numbers (1.1, 4.1.1.. so on)", id="pir_observed")
			
			yield Label("Artifact Type")
			yield Input(placeholder="Command, Exploit, File, FQDN, IPv4, IPv6, Tool, etc.", id="pir_artifact_type")
			
			yield Label("Artifact Details")
			yield Input(placeholder="Command, Filepath, IP address, domain, tool name, etc.", id="pir_artifact_details")
			
			yield Label("Location Found")
			yield Input(placeholder="System/location where artifact was found (e.g., ENG-WS-WIN-001)", id="pir_location")
			
			yield Label("MD5 Hash (If Applicable)")
			yield Input(placeholder="MD5 hash of file artifact", id="pir_md5")
			
			yield Label("SHA-1 Hash (If Applicable)")
			yield Input(placeholder="SHA-1 hash of file artifact", id="pir_sha1")
			
			yield Label("SHA-256 Hash (If Applicable)")
			yield Input(placeholder="SHA-256 hash of file artifact", id="pir_sha256")
			
			yield Label("Narrative")
			yield Input(placeholder="Context explaining why this is an IoC/IoA/Important to Fusion Cell", id="pir_narrative")

	def create_rfc_content(self) -> ComposeResult:
		with Horizontal(id="RFCButtons"):
			yield Button("Create RFC Report", id="save_rfc_button")
			yield Button("Clear RFC Form", id="clear_rfc_button")

		yield Label("RFC (Request for Change) Report", id="rfc_main_label")
		
		with Collapsible(id="rfc_form", collapsed=False):
			yield Label("Submitted Status")
			yield Select.from_values(rfc_status, allow_blank=False, id="rfc_submitted_status")
			
			yield Label("Status Change")
			yield Input(placeholder="Any status updates or changes", id="rfc_status_change")
			
			yield Label("Description")
			yield Input(placeholder="Detailed description of the change request", id="rfc_description")
			
			yield Label("Subnet")
			yield Input(placeholder="Network subnet affected (e.g., 10.6.14.0)", id="rfc_subnet")
			
			yield Label("Host")
			yield Input(placeholder="Specific host or system name", id="rfc_host")
			
			yield Label("Role")
			yield Select.from_values(rfc_role, allow_blank=False, id="rfc_role_type")
			
			yield Label("IP Address")
			yield Input(placeholder="IP address of affected system", id="rfc_ip_address")
			
			yield Label("Justification")
			yield Input(placeholder="Business justification for this change", id="rfc_justification")
			
			yield Label("Reporter")
			yield Input(placeholder="Person/team reporting this RFC", id="rfc_reporter")
			
			yield Label("Severity")
			yield Select.from_values(rfc_severity, allow_blank=False, id="rfc_severity_level")

	def create_spot_content(self) -> ComposeResult:
		with Horizontal(id="SPOTButtons"):
			yield Button("Create SPOT Report", id="save_spot_button")
			yield Button("Clear SPOT Form", id="clear_spot_button")

		yield Label("SPOT Report (Situational Report)", id="spot_main_label")
		
		with Collapsible(id="spot_form", collapsed=False):
			yield Label("Date-Time-Group (DTG)")
			yield Input(placeholder="DDHHMMZMONYY (e.g., 121430ZDEC24)", id="spot_dtg")
			
			yield Label("Size")
			yield Select.from_values(unit_sizes, allow_blank=False, id="spot_size")
			
			yield Label("Activity")
			yield Input(placeholder="What is happening", id="spot_activity")
			
			yield Label("Location")
			yield Input(placeholder="Where is it happening", id="spot_location")
			
			yield Label("Unit/System")
			yield Input(placeholder="Who/what is involved", id="spot_unit")
			
			yield Label("Time")
			yield Input(placeholder="When did it occur", id="spot_time")
			
			yield Label("Equipment")
			yield Input(placeholder="Equipment involved", id="spot_equipment")
			
			yield Label("Reporter")
			yield Input(placeholder="Who is reporting", id="spot_reporter")

	def create_sitrep_content(self) -> ComposeResult:
		with Horizontal(id="SITREPButtons"):
			yield Button("Create SITREP", id="save_sitrep_button")
			yield Button("Clear SITREP Form", id="clear_sitrep_button")

		yield Label("SITREP (Situation Report)", id="sitrep_main_label")
		
		with Collapsible(id="sitrep_form", collapsed=False):
			yield Label("Date-Time-Group")
			yield Input(placeholder="DDHHMMZMONYY", id="sitrep_dtg")
			
			yield Label("Current Situation")
			yield Input(placeholder="Current operational status", id="sitrep_current_situation")
			
			yield Label("Actions Taken")
			yield Input(placeholder="Actions completed since last report", id="sitrep_actions_taken")
			
			yield Label("Enemy/Threat Activity")
			yield Input(placeholder="Observed threat activity", id="sitrep_threat_activity")
			
			yield Label("Friendly Status")
			yield Input(placeholder="Status of friendly forces/systems", id="sitrep_friendly_status")
			
			yield Label("Next Actions")
			yield Input(placeholder="Planned next steps", id="sitrep_next_actions")
			
			yield Label("Timeline")
			yield Input(placeholder="Expected timeline for actions", id="sitrep_timeline")
			
			yield Label("Reporter")
			yield Input(placeholder="Situation reporter", id="sitrep_reporter")

	def create_aar_content(self) -> ComposeResult:
		with Horizontal(id="AARButtons"):
			yield Button("Create AAR", id="save_aar_button")
			yield Button("Clear AAR Form", id="clear_aar_button")

		yield Label("AAR (After Action Report)", id="aar_main_label")
		
		with Collapsible(id="aar_form", collapsed=False):
			yield Label("Mission/Operation Summary")
			yield Input(placeholder="Brief summary of the operation", id="aar_mission_summary")
			
			yield Label("What Went Well (Sustain)")
			yield Input(placeholder="Successful aspects to continue", id="aar_went_well")
			
			yield Label("What Needs Improvement (Improve)")
			yield Input(placeholder="Areas requiring improvement", id="aar_needs_improvement")
			
			yield Label("Recommendations")
			yield Input(placeholder="Specific recommendations for future operations", id="aar_recommendations")
			
			yield Label("Training Needs")
			yield Input(placeholder="Identified training requirements", id="aar_training_needs")
			
			yield Label("Resource Requirements")
			yield Input(placeholder="Additional resources needed", id="aar_resource_requirements")
			
			yield Label("Timeline")
			yield Input(placeholder="Operation start and end times", id="aar_timeline")
			
			yield Label("Reporter")
			yield Input(placeholder="AAR author", id="aar_reporter")

	def create_vuln_content(self) -> ComposeResult:
		with Horizontal(id="VulnButtons"):
			yield Button("Create Vulnerability Assessment", id="save_vuln_button")
			yield Button("Clear Vulnerability Form", id="clear_vuln_button")

		yield Label("Vulnerability Assessment Report", id="vuln_main_label")
		
		with Collapsible(id="vuln_form", collapsed=False):
			yield Label("System Details")
			yield Input(placeholder="Affected system information", id="vuln_system_details")
			
			yield Label("Vulnerability Description")
			yield Input(placeholder="Detailed vulnerability description", id="vuln_description")
			
			yield Label("CVSS Score")
			yield Select.from_values(cvss_scores, allow_blank=False, id="vuln_cvss_score")
			
			yield Label("Exploitation Difficulty")
			yield Input(placeholder="How difficult to exploit", id="vuln_exploitation_difficulty")
			
			yield Label("Impact")
			yield Input(placeholder="Potential impact if exploited", id="vuln_impact")
			
			yield Label("Remediation Steps")
			yield Input(placeholder="Steps to fix the vulnerability", id="vuln_remediation")
			
			yield Label("Discovery Date")
			yield Input(placeholder="When vulnerability was discovered", id="vuln_discovery_date")
			
			yield Label("Reporter")
			yield Input(placeholder="Vulnerability assessor", id="vuln_reporter")

	def on_mount(self) -> None:
		os.makedirs(REPORTS_DIR, exist_ok=True)

	def sanitize_filename_part(self, text: str) -> str:
		"""Sanitize text for use in filename - remove spaces and special chars"""
		if not text:
			return "Unknown"
		# Remove special characters and replace spaces with underscores
		sanitized = re.sub(r'[^\w\s-]', '', str(text))
		sanitized = re.sub(r'\s+', '', sanitized)  # Remove all spaces
		return sanitized[:30]  # Limit length

	def collect_pir_data(self) -> dict:
		timestamp_enclave = self.query_one("#pir_timestamp_enclave").value or f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC - UNKNOWN_ENCLAVE"
		artifact_type = self.query_one("#pir_artifact_type").value or "Unknown"
		artifact_details = self.query_one("#pir_artifact_details").value or "Unknown"
		date_and_time = self.get_current_datetime()

		data = {}
		pir_fields = [
			"pir_timestamp_enclave", "pir_observed", "pir_artifact_type", 
			"pir_artifact_details", "pir_location", "pir_md5", "pir_sha1", 
			"pir_sha256", "pir_narrative"
		]
		
		for field_id in pir_fields:
			widget = self.query_one(f"#{field_id}")
			data[field_id] = widget.value or None

		# New filename format: YYYYMMDD_HHMMUTC_PIR_ArtifactTypeDetails
		sanitized_type = self.sanitize_filename_part(artifact_type)
		sanitized_details = self.sanitize_filename_part(artifact_details)
		file_name = f"{date_and_time}_PIR_{sanitized_type}_{sanitized_details}"
		file_path = os.path.join(REPORTS_DIR, f"{file_name}.json")

		with open(file_path, "w") as f:
			json.dump(data, f, indent=4)

		self.create_pir_txt_report(data, file_name)
		self.create_pdf(data, file_name, "PIR")
		return file_name

	def collect_rfc_data(self) -> dict:
		submitted_status = self.query_one("#rfc_submitted_status").value or "NotSubmitted"
		severity = self.query_one("#rfc_severity_level").value or "Medium"
		description = self.query_one("#rfc_description").value or "Unknown"
		date_and_time = self.get_current_datetime()

		data = {}
		rfc_fields = [
			"rfc_submitted_status", "rfc_status_change", "rfc_description", 
			"rfc_subnet", "rfc_host", "rfc_role_type", "rfc_ip_address", 
			"rfc_justification", "rfc_reporter", "rfc_severity_level"
		]
		
		for field_id in rfc_fields:
			widget = self.query_one(f"#{field_id}")
			data[field_id] = widget.value or None

		# New filename format: YYYYMMDD_HHMMUTC_RFC_SeverityDescription
		sanitized_severity = self.sanitize_filename_part(severity)
		sanitized_desc = self.sanitize_filename_part(description)
		file_name = f"{date_and_time}_RFC_{sanitized_severity}_{sanitized_desc}"
		file_path = os.path.join(REPORTS_DIR, f"{file_name}.json")

		with open(file_path, "w") as f:
			json.dump(data, f, indent=4)

		self.create_rfc_txt_report(data, file_name)
		self.create_pdf(data, file_name, "RFC")
		return file_name

	def collect_spot_data(self) -> dict:
		size = self.query_one("#spot_size").value or "Unknown"
		activity = self.query_one("#spot_activity").value or "Unknown"
		date_and_time = self.get_current_datetime()
		data = {}
		spot_fields = ["spot_dtg", "spot_size", "spot_activity", "spot_location", "spot_unit", "spot_time", "spot_equipment", "spot_reporter"]
		for field_id in spot_fields:
			widget = self.query_one(f"#{field_id}")
			data[field_id] = widget.value or None
		
		# New filename format: YYYYMMDD_HHMMUTC_SPOT_SizeActivity
		sanitized_size = self.sanitize_filename_part(size)
		sanitized_activity = self.sanitize_filename_part(activity)
		file_name = f"{date_and_time}_SPOT_{sanitized_size}_{sanitized_activity}"
		file_path = os.path.join(REPORTS_DIR, f"{file_name}.json")
		
		with open(file_path, "w") as f:
			json.dump(data, f, indent=4)
		self.create_spot_txt_report(data, file_name)
		self.create_pdf(data, file_name, "SPOT")
		return file_name

	def collect_sitrep_data(self) -> dict:
		situation = self.query_one("#sitrep_current_situation").value or "Unknown"
		date_and_time = self.get_current_datetime()
		data = {}
		sitrep_fields = ["sitrep_dtg", "sitrep_current_situation", "sitrep_actions_taken", "sitrep_threat_activity", "sitrep_friendly_status", "sitrep_next_actions", "sitrep_timeline", "sitrep_reporter"]
		for field_id in sitrep_fields:
			widget = self.query_one(f"#{field_id}")
			data[field_id] = widget.value or None
		
		# New filename format: YYYYMMDD_HHMMUTC_SITREP_Situation
		sanitized_situation = self.sanitize_filename_part(situation)
		file_name = f"{date_and_time}_SITREP_{sanitized_situation}"
		file_path = os.path.join(REPORTS_DIR, f"{file_name}.json")
		
		with open(file_path, "w") as f:
			json.dump(data, f, indent=4)
		self.create_sitrep_txt_report(data, file_name)
		self.create_pdf(data, file_name, "SITREP")
		return file_name

	def collect_aar_data(self) -> dict:
		mission = self.query_one("#aar_mission_summary").value or "Unknown"
		date_and_time = self.get_current_datetime()
		data = {}
		aar_fields = ["aar_mission_summary", "aar_went_well", "aar_needs_improvement", "aar_recommendations", "aar_training_needs", "aar_resource_requirements", "aar_timeline", "aar_reporter"]
		for field_id in aar_fields:
			widget = self.query_one(f"#{field_id}")
			data[field_id] = widget.value or None
		
		# New filename format: YYYYMMDD_HHMMUTC_AAR_Mission
		sanitized_mission = self.sanitize_filename_part(mission)
		file_name = f"{date_and_time}_AAR_{sanitized_mission}"
		file_path = os.path.join(REPORTS_DIR, f"{file_name}.json")
		
		with open(file_path, "w") as f:
			json.dump(data, f, indent=4)
		self.create_aar_txt_report(data, file_name)
		self.create_pdf(data, file_name, "AAR")
		return file_name

	def collect_vuln_data(self) -> dict:
		cvss = self.query_one("#vuln_cvss_score").value or "Unknown"
		system = self.query_one("#vuln_system_details").value or "Unknown"
		date_and_time = self.get_current_datetime()
		data = {}
		vuln_fields = ["vuln_system_details", "vuln_description", "vuln_cvss_score", "vuln_exploitation_difficulty", "vuln_impact", "vuln_remediation", "vuln_discovery_date", "vuln_reporter"]
		for field_id in vuln_fields:
			widget = self.query_one(f"#{field_id}")
			data[field_id] = widget.value or None
		
		# New filename format: YYYYMMDD_HHMMUTC_VULN_CVSSSystem
		sanitized_cvss = self.sanitize_filename_part(cvss.replace(' ', '_').replace('.', '_'))
		sanitized_system = self.sanitize_filename_part(system)
		file_name = f"{date_and_time}_VULN_{sanitized_cvss}_{sanitized_system}"
		file_path = os.path.join(REPORTS_DIR, f"{file_name}.json")
		
		with open(file_path, "w") as f:
			json.dump(data, f, indent=4)
		self.create_vuln_txt_report(data, file_name)
		self.create_pdf(data, file_name, "VULNERABILITY")
		return file_name

	def create_pir_txt_report(self, data, file_name):
		"""Create a simple text file in the PIR format"""
		txt_path = os.path.join(REPORTS_DIR, f"{file_name}.txt")
		
		try:
			with open(txt_path, "w") as f:
				f.write("=== PIR REPORT ===\n\n")
				f.write(f"Line 1: {data.get('pir_timestamp_enclave', 'N/A')}\n")
				f.write(f"Line 2: {data.get('pir_observed', 'N/A')}\n")
				f.write(f"Line 3: {data.get('pir_artifact_type', 'N/A')}\n")
				f.write(f"Line 4: {data.get('pir_artifact_details', 'N/A')}\n")
				f.write(f"Line 5: {data.get('pir_location', 'N/A')}\n")
				f.write(f"Line 6 (md5): {data.get('pir_md5', 'N/A')}\n")
				f.write(f"Line 7 (sha1): {data.get('pir_sha1', 'N/A')}\n")
				f.write(f"Line 8 (sha256): {data.get('pir_sha256', 'N/A')}\n")
				f.write(f"Line 9: {data.get('pir_narrative', 'N/A')}\n")
				f.write(f"\n=== END PIR REPORT ===\n")
			
			print(f"PIR TXT report successfully created at: {txt_path}")
		except Exception as e:
			print(f"Error creating PIR TXT report: {e}")

	def create_rfc_txt_report(self, data, file_name):
		"""Create a simple text file in the RFC format"""
		txt_path = os.path.join(REPORTS_DIR, f"{file_name}.txt")
		
		try:
			with open(txt_path, "w") as f:
				f.write("=== RFC (REQUEST FOR CHANGE) REPORT ===\n\n")
				f.write(f"Submitted Status: {data.get('rfc_submitted_status', 'N/A')}\n")
				f.write(f"Status Change: {data.get('rfc_status_change', 'N/A')}\n")
				f.write(f"Description: {data.get('rfc_description', 'N/A')}\n")
				f.write(f"Subnet: {data.get('rfc_subnet', 'N/A')}\n")
				f.write(f"Host: {data.get('rfc_host', 'N/A')}\n")
				f.write(f"Role: {data.get('rfc_role_type', 'N/A')}\n")
				f.write(f"IP Address: {data.get('rfc_ip_address', 'N/A')}\n")
				f.write(f"Justification: {data.get('rfc_justification', 'N/A')}\n")
				f.write(f"Reporter: {data.get('rfc_reporter', 'N/A')}\n")
				f.write(f"Severity: {data.get('rfc_severity_level', 'N/A')}\n")
				f.write(f"\n=== END RFC REPORT ===\n")
			
			print(f"RFC TXT report successfully created at: {txt_path}")
		except Exception as e:
			print(f"Error creating RFC TXT report: {e}")

	def create_spot_txt_report(self, data, file_name):
		txt_path = os.path.join(REPORTS_DIR, f"{file_name}.txt")
		try:
			with open(txt_path, "w") as f:
				f.write("=== SPOT REPORT (SALUTE FORMAT) ===\n\n")
				f.write(f"DTG: {data.get('spot_dtg', 'N/A')}\n")
				f.write(f"Size: {data.get('spot_size', 'N/A')}\n")
				f.write(f"Activity: {data.get('spot_activity', 'N/A')}\n")
				f.write(f"Location: {data.get('spot_location', 'N/A')}\n")
				f.write(f"Unit: {data.get('spot_unit', 'N/A')}\n")
				f.write(f"Time: {data.get('spot_time', 'N/A')}\n")
				f.write(f"Equipment: {data.get('spot_equipment', 'N/A')}\n")
				f.write(f"Reporter: {data.get('spot_reporter', 'N/A')}\n")
				f.write(f"\n=== END SPOT REPORT ===\n")
			print(f"SPOT TXT report successfully created at: {txt_path}")
		except Exception as e:
			print(f"Error creating SPOT TXT report: {e}")

	def create_sitrep_txt_report(self, data, file_name):
		txt_path = os.path.join(REPORTS_DIR, f"{file_name}.txt")
		try:
			with open(txt_path, "w") as f:
				f.write("=== SITUATION REPORT (SITREP) ===\n\n")
				f.write(f"DTG: {data.get('sitrep_dtg', 'N/A')}\n")
				f.write(f"Current Situation: {data.get('sitrep_current_situation', 'N/A')}\n")
				f.write(f"Actions Taken: {data.get('sitrep_actions_taken', 'N/A')}\n")
				f.write(f"Threat Activity: {data.get('sitrep_threat_activity', 'N/A')}\n")
				f.write(f"Friendly Status: {data.get('sitrep_friendly_status', 'N/A')}\n")
				f.write(f"Next Actions: {data.get('sitrep_next_actions', 'N/A')}\n")
				f.write(f"Timeline: {data.get('sitrep_timeline', 'N/A')}\n")
				f.write(f"Reporter: {data.get('sitrep_reporter', 'N/A')}\n")
				f.write(f"\n=== END SITREP ===\n")
			print(f"SITREP TXT report successfully created at: {txt_path}")
		except Exception as e:
			print(f"Error creating SITREP TXT report: {e}")

	def create_aar_txt_report(self, data, file_name):
		txt_path = os.path.join(REPORTS_DIR, f"{file_name}.txt")
		try:
			with open(txt_path, "w") as f:
				f.write("=== AFTER ACTION REPORT (AAR) ===\n\n")
				f.write(f"Mission Summary: {data.get('aar_mission_summary', 'N/A')}\n")
				f.write(f"What Went Well: {data.get('aar_went_well', 'N/A')}\n")
				f.write(f"Needs Improvement: {data.get('aar_needs_improvement', 'N/A')}\n")
				f.write(f"Recommendations: {data.get('aar_recommendations', 'N/A')}\n")
				f.write(f"Training Needs: {data.get('aar_training_needs', 'N/A')}\n")
				f.write(f"Resource Requirements: {data.get('aar_resource_requirements', 'N/A')}\n")
				f.write(f"Timeline: {data.get('aar_timeline', 'N/A')}\n")
				f.write(f"Reporter: {data.get('aar_reporter', 'N/A')}\n")
				f.write(f"\n=== END AAR ===\n")
			print(f"AAR TXT report successfully created at: {txt_path}")
		except Exception as e:
			print(f"Error creating AAR TXT report: {e}")

	def create_vuln_txt_report(self, data, file_name):
		txt_path = os.path.join(REPORTS_DIR, f"{file_name}.txt")
		try:
			with open(txt_path, "w") as f:
				f.write("=== VULNERABILITY ASSESSMENT REPORT ===\n\n")
				f.write(f"System Details: {data.get('vuln_system_details', 'N/A')}\n")
				f.write(f"Vulnerability Description: {data.get('vuln_description', 'N/A')}\n")
				f.write(f"CVSS Score: {data.get('vuln_cvss_score', 'N/A')}\n")
				f.write(f"Exploitation Difficulty: {data.get('vuln_exploitation_difficulty', 'N/A')}\n")
				f.write(f"Impact: {data.get('vuln_impact', 'N/A')}\n")
				f.write(f"Remediation Steps: {data.get('vuln_remediation', 'N/A')}\n")
				f.write(f"Discovery Date: {data.get('vuln_discovery_date', 'N/A')}\n")
				f.write(f"Reporter: {data.get('vuln_reporter', 'N/A')}\n")
				f.write(f"\n=== END VULNERABILITY ASSESSMENT ===\n")
			print(f"Vulnerability Assessment TXT report successfully created at: {txt_path}")
		except Exception as e:
			print(f"Error creating Vulnerability Assessment TXT report: {e}")

	def clear_pir_form(self):
		"""Clear all PIR form fields"""
		pir_fields = [
			"pir_timestamp_enclave", "pir_observed", "pir_artifact_type", 
			"pir_artifact_details", "pir_location", "pir_md5", "pir_sha1", 
			"pir_sha256", "pir_narrative"
		]
		
		for field_id in pir_fields:
			try:
				widget = self.query_one(f"#{field_id}")
				if hasattr(widget, 'value'):
					widget.value = ""
			except:
				pass  # Field might not exist, continue

	def clear_rfc_form(self):
		"""Clear all RFC form fields"""
		rfc_fields = [
			"rfc_submitted_status", "rfc_status_change", "rfc_description", 
			"rfc_subnet", "rfc_host", "rfc_role_type", "rfc_ip_address", 
			"rfc_justification", "rfc_reporter", "rfc_severity_level"
		]
		
		for field_id in rfc_fields:
			try:
				widget = self.query_one(f"#{field_id}")
				if hasattr(widget, 'value'):
					if isinstance(widget, Select):
						widget.value = "null"
					else:
						widget.value = ""
			except:
				pass  # Field might not exist, continue

	def clear_spot_form(self):
		"""Clear all SPOT form fields"""
		spot_fields = ["spot_dtg", "spot_size", "spot_activity", "spot_location", "spot_unit", "spot_time", "spot_equipment", "spot_reporter"]
		for field_id in spot_fields:
			try:
				widget = self.query_one(f"#{field_id}")
				if hasattr(widget, 'value'):
					if isinstance(widget, Select):
						widget.value = "null"
					else:
						widget.value = ""
			except:
				pass

	def clear_sitrep_form(self):
		"""Clear all SITREP form fields"""
		sitrep_fields = ["sitrep_dtg", "sitrep_current_situation", "sitrep_actions_taken", "sitrep_threat_activity", "sitrep_friendly_status", "sitrep_next_actions", "sitrep_timeline", "sitrep_reporter"]
		for field_id in sitrep_fields:
			try:
				widget = self.query_one(f"#{field_id}")
				if hasattr(widget, 'value'):
					widget.value = ""
			except:
				pass

	def clear_aar_form(self):
		"""Clear all AAR form fields"""
		aar_fields = ["aar_mission_summary", "aar_went_well", "aar_needs_improvement", "aar_recommendations", "aar_training_needs", "aar_resource_requirements", "aar_timeline", "aar_reporter"]
		for field_id in aar_fields:
			try:
				widget = self.query_one(f"#{field_id}")
				if hasattr(widget, 'value'):
					widget.value = ""
			except:
				pass

	def clear_vuln_form(self):
		"""Clear all Vulnerability Assessment form fields"""
		vuln_fields = ["vuln_system_details", "vuln_description", "vuln_cvss_score", "vuln_exploitation_difficulty", "vuln_impact", "vuln_remediation", "vuln_discovery_date", "vuln_reporter"]
		for field_id in vuln_fields:
			try:
				widget = self.query_one(f"#{field_id}")
				if hasattr(widget, 'value'):
					if isinstance(widget, Select):
						widget.value = "null"
					else:
						widget.value = ""
			except:
				pass

	def get_current_datetime(self):
		"""Return current datetime in UTC with UTC suffix"""
		return datetime.utcnow().strftime("%Y%m%d_%H%M") + "UTC"

	def create_pdf(self, data, file_name, report_type):
		"""Create a PDF report for any report type"""
		try:
			from reportlab.lib.pagesizes import letter
			from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
			from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
			from reportlab.lib import colors
			from reportlab.lib.units import inch
			from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY

			pdf_path = os.path.join(REPORTS_DIR, f"{file_name}.pdf")
			doc = SimpleDocTemplate(
				pdf_path, 
				pagesize=letter,
				rightMargin=0.75*inch,
				leftMargin=0.75*inch,
				topMargin=1*inch,
				bottomMargin=1*inch
			)
			
			# Create custom styles
			styles = getSampleStyleSheet()
			
			# Title style
			title_style = ParagraphStyle(
				'CustomTitle',
				parent=styles['Title'],
				fontSize=24,
				spaceAfter=30,
				alignment=TA_CENTER,
				textColor=colors.darkblue
			)
			
			# Section header style
			section_style = ParagraphStyle(
				'SectionHeader',
				parent=styles['Heading1'],
				fontSize=16,
				spaceAfter=12,
				spaceBefore=20,
				textColor=colors.darkblue,
				borderWidth=2,
				borderColor=colors.darkblue,
				borderPadding=5,
				backColor=colors.lightgrey
			)
			
			# Subsection style
			subsection_style = ParagraphStyle(
				'SubsectionHeader',
				parent=styles['Heading2'],
				fontSize=14,
				spaceAfter=8,
				spaceBefore=12,
				textColor=colors.darkred,
				leftIndent=10
			)
			
			# Normal text with better spacing
			normal_style = ParagraphStyle(
				'CustomNormal',
				parent=styles['Normal'],
				fontSize=10,
				spaceAfter=6,
				alignment=TA_LEFT,
				wordWrap='CJK'
			)
			
			# Value text style for table content
			value_style = ParagraphStyle(
				'ValueText',
				parent=styles['Normal'],
				fontSize=10,
				spaceAfter=3,
				alignment=TA_LEFT,
				wordWrap='CJK',
				allowWidows=1,
				allowOrphans=1
			)
			
			# Info box style
			info_style = ParagraphStyle(
				'InfoBox',
				parent=styles['Normal'],
				fontSize=9,
				textColor=colors.darkblue,
				backColor=colors.lightblue,
				borderWidth=1,
				borderColor=colors.blue,
				borderPadding=8,
				spaceAfter=12
			)

			elements = []

			# Title page
			elements.append(Paragraph(f"{report_type.upper()} REPORT", title_style))
			elements.append(Spacer(1, 0.5*inch))
			
			# Get report-specific sections
			sections = self.get_report_sections(data, report_type)
			
			# Executive summary box
			exec_summary = f"""
			<b>Report Type:</b> {report_type.upper()}<br/>
			<b>Report Generated:</b> {datetime.utcnow().strftime('%B %d, %Y at %H:%M')} UTC<br/>
			<b>File Name:</b> {file_name}.pdf
			"""
			elements.append(Paragraph(exec_summary, info_style))
			elements.append(Spacer(1, 0.3*inch))

			# elements.append(PageBreak())

			# Process each section
			for section_title, key_value_pairs in sections:
				# Add section header
				elements.append(Paragraph(section_title, section_style))
				
				# Check if section has any meaningful data
				has_data = any(value and value.strip() and value != 'N/A' for _, value in key_value_pairs)
				
				if not has_data:
					elements.append(Paragraph("<i>No information available for this section.</i>", normal_style))
					elements.append(Spacer(1, 12))
					continue
				
				# Create a more sophisticated table
				table_data = []
				for key, value in key_value_pairs:
					if value and value.strip() and value != 'N/A':
						# Always wrap values in Paragraph for proper text wrapping
						wrapped_key = Paragraph(f"<b>{key}</b>", normal_style)
						wrapped_value = Paragraph(str(value), value_style)
						table_data.append([wrapped_key, wrapped_value])
				
				if table_data:
					table = Table(table_data, colWidths=[2.2*inch, 4.3*inch], repeatRows=0)
					table.setStyle(TableStyle([
						# Header styling
						('BACKGROUND', (0, 0), (-1, -1), colors.white),
						('TEXTCOLOR', (0, 0), (0, -1), colors.darkblue),  # Key column
						('TEXTCOLOR', (1, 0), (1, -1), colors.black),     # Value column
						
						# Alignment
						('ALIGN', (0, 0), (0, -1), 'LEFT'),
						('ALIGN', (1, 0), (1, -1), 'LEFT'),
						('VALIGN', (0, 0), (-1, -1), 'TOP'),
						
						# Borders and grid
						('GRID', (0, 0), (-1, -1), 0.75, colors.grey),
						('LINEBELOW', (0, 0), (-1, 0), 1.5, colors.darkblue),
						
						# Padding - increased for better spacing
						('LEFTPADDING', (0, 0), (-1, -1), 10),
						('RIGHTPADDING', (0, 0), (-1, -1), 10),
						('TOPPADDING', (0, 0), (-1, -1), 8),
						('BOTTOMPADDING', (0, 0), (-1, -1), 8),
						
						# Alternating row colors for better readability
						('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.lightblue, colors.lightgrey]),
						
						# Word wrap and text handling
						('FONTSIZE', (0, 0), (-1, -1), 10),
						('LEADING', (0, 0), (-1, -1), 12),
					]))
					
					# Wrap table in KeepTogether to avoid awkward page breaks
					elements.append(KeepTogether(table))
				
				elements.append(Spacer(1, 20))

			# Add footer with metadata
			elements.append(PageBreak())
			elements.append(Paragraph("Report Metadata", section_style))
			
			metadata_data = [
				[Paragraph("<b>Report Generated</b>", normal_style), 
				 Paragraph(datetime.utcnow().strftime('%B %d, %Y at %H:%M:%S') + " UTC", value_style)],
				[Paragraph("<b>Report Type</b>", normal_style), 
				 Paragraph(report_type.upper(), value_style)],
				[Paragraph("<b>File Name</b>", normal_style), 
				 Paragraph(file_name, value_style)],
				[Paragraph("<b>Report Version</b>", normal_style), 
				 Paragraph("1.0", value_style)],
			]
			
			metadata_table = Table(metadata_data, colWidths=[2.2*inch, 4.3*inch])
			
			metadata_table.setStyle(TableStyle([
				('BACKGROUND', (0, 0), (-1, -1), colors.lightblue),
				('TEXTCOLOR', (0, 0), (-1, -1), colors.darkblue),
				('ALIGN', (0, 0), (-1, -1), 'LEFT'),
				('VALIGN', (0, 0), (-1, -1), 'TOP'),
				('FONTSIZE', (0, 0), (-1, -1), 10),
				('GRID', (0, 0), (-1, -1), 1, colors.darkblue),
				('LEFTPADDING', (0, 0), (-1, -1), 10),
				('RIGHTPADDING', (0, 0), (-1, -1), 10),
				('TOPPADDING', (0, 0), (-1, -1), 8),
				('BOTTOMPADDING', (0, 0), (-1, -1), 8),
				('LEADING', (0, 0), (-1, -1), 12),
			]))
			
			elements.append(metadata_table)

			# Build the PDF
			doc.build(elements)
			print(f"PDF successfully created at: {pdf_path}")
		except Exception as e:
			print(f"Error creating PDF: {e}")
			# Fallback to basic PDF if advanced features fail
			self.create_basic_pdf_fallback(data, file_name, report_type)

	def get_report_sections(self, data, report_type):
		"""Get the appropriate sections for each report type"""
		if report_type == "PIR":
			return [
				("PIR INFORMATION", [
					("Timestamp and Enclave", data.get('pir_timestamp_enclave', 'N/A')),
					("PIR(s) Observed", data.get('pir_observed', 'N/A')),
					("Artifact Type", data.get('pir_artifact_type', 'N/A')),
					("Artifact Details", data.get('pir_artifact_details', 'N/A')),
					("Location Found", data.get('pir_location', 'N/A')),
					("Narrative", data.get('pir_narrative', 'N/A')),
				]),
				("HASH INFORMATION", [
					("MD5 Hash", data.get('pir_md5', 'N/A')),
					("SHA-1 Hash", data.get('pir_sha1', 'N/A')),
					("SHA-256 Hash", data.get('pir_sha256', 'N/A')),
				]),
			]
		elif report_type == "RFC":
			return [
				("REQUEST FOR CHANGE DETAILS", [
					("Submitted Status", data.get('rfc_submitted_status', 'N/A')),
					("Status Change", data.get('rfc_status_change', 'N/A')),
					("Description", data.get('rfc_description', 'N/A')),
					("Justification", data.get('rfc_justification', 'N/A')),
					("Reporter", data.get('rfc_reporter', 'N/A')),
					("Severity", data.get('rfc_severity_level', 'N/A')),
				]),
				("SYSTEM INFORMATION", [
					("Subnet", data.get('rfc_subnet', 'N/A')),
					("Host", data.get('rfc_host', 'N/A')),
					("Role", data.get('rfc_role_type', 'N/A')),
					("IP Address", data.get('rfc_ip_address', 'N/A')),
				]),
			]
		elif report_type == "SPOT":
			return [
				("SPOT REPORT (SALUTE FORMAT)", [
					("Date-Time-Group", data.get('spot_dtg', 'N/A')),
					("Size", data.get('spot_size', 'N/A')),
					("Activity", data.get('spot_activity', 'N/A')),
					("Location", data.get('spot_location', 'N/A')),
					("Unit/System", data.get('spot_unit', 'N/A')),
					("Time", data.get('spot_time', 'N/A')),
					("Equipment", data.get('spot_equipment', 'N/A')),
					("Reporter", data.get('spot_reporter', 'N/A')),
				]),
			]
		elif report_type == "SITREP":
			return [
				("SITUATION REPORT", [
					("Date-Time-Group", data.get('sitrep_dtg', 'N/A')),
					("Current Situation", data.get('sitrep_current_situation', 'N/A')),
					("Actions Taken", data.get('sitrep_actions_taken', 'N/A')),
					("Enemy/Threat Activity", data.get('sitrep_threat_activity', 'N/A')),
					("Friendly Status", data.get('sitrep_friendly_status', 'N/A')),
					("Next Actions", data.get('sitrep_next_actions', 'N/A')),
					("Timeline", data.get('sitrep_timeline', 'N/A')),
					("Reporter", data.get('sitrep_reporter', 'N/A')),
				]),
			]
		elif report_type == "AAR":
			return [
				("AFTER ACTION REPORT", [
					("Mission/Operation Summary", data.get('aar_mission_summary', 'N/A')),
					("What Went Well (Sustain)", data.get('aar_went_well', 'N/A')),
					("What Needs Improvement", data.get('aar_needs_improvement', 'N/A')),
					("Recommendations", data.get('aar_recommendations', 'N/A')),
					("Training Needs", data.get('aar_training_needs', 'N/A')),
					("Resource Requirements", data.get('aar_resource_requirements', 'N/A')),
					("Timeline", data.get('aar_timeline', 'N/A')),
					("Reporter", data.get('aar_reporter', 'N/A')),
				]),
			]
		elif report_type == "VULNERABILITY":
			return [
				("VULNERABILITY ASSESSMENT", [
					("System Details", data.get('vuln_system_details', 'N/A')),
					("Vulnerability Description", data.get('vuln_description', 'N/A')),
					("CVSS Score", data.get('vuln_cvss_score', 'N/A')),
					("Exploitation Difficulty", data.get('vuln_exploitation_difficulty', 'N/A')),
					("Impact", data.get('vuln_impact', 'N/A')),
					("Remediation Steps", data.get('vuln_remediation', 'N/A')),
					("Discovery Date", data.get('vuln_discovery_date', 'N/A')),
					("Reporter", data.get('vuln_reporter', 'N/A')),
				]),
			]
		else:
			return [("UNKNOWN REPORT TYPE", [])]

	def create_basic_pdf_fallback(self, data, file_name, report_type):
		"""Fallback PDF creation method with minimal dependencies"""
		try:
			from reportlab.lib.pagesizes import letter
			from reportlab.platypus import SimpleDocTemplate, Paragraph
			from reportlab.lib.styles import getSampleStyleSheet
			
			pdf_path = os.path.join(REPORTS_DIR, f"{file_name}_basic.pdf")
			doc = SimpleDocTemplate(pdf_path, pagesize=letter)
			styles = getSampleStyleSheet()
			elements = []
			
			elements.append(Paragraph(f"{report_type.upper()} REPORT", styles['Title']))
			for key, value in data.items():
				if value:
					elements.append(Paragraph(f"<b>{key}:</b> {value}", styles['Normal']))
			
			doc.build(elements)
			print(f"Basic PDF created at: {pdf_path}")
		except Exception as e:
			print(f"Could not create fallback PDF: {e}")

	def on_button_pressed(self, event: Button.Pressed) -> None:
		if event.button.id == "save_pir_button":
			file_name = self.collect_pir_data()
			self.push_screen(SaveScreen(f"PIR Report created: {file_name}"))
		elif event.button.id == "clear_pir_button":
			self.clear_pir_form()
		elif event.button.id == "get_current_pir_button":
			self.push_screen(FileListModal("PIR"))
		elif event.button.id == "save_rfc_button":
			file_name = self.collect_rfc_data()
			self.push_screen(SaveScreen(f"RFC Report created: {file_name}"))
		elif event.button.id == "clear_rfc_button":
			self.clear_rfc_form()
		elif event.button.id == "save_spot_button":
			file_name = self.collect_spot_data()
			self.push_screen(SaveScreen(f"SPOT Report created: {file_name}"))
		elif event.button.id == "clear_spot_button":
			self.clear_spot_form()
		elif event.button.id == "save_sitrep_button":
			file_name = self.collect_sitrep_data()
			self.push_screen(SaveScreen(f"SITREP created: {file_name}"))
		elif event.button.id == "clear_sitrep_button":
			self.clear_sitrep_form()
		elif event.button.id == "save_aar_button":
			file_name = self.collect_aar_data()
			self.push_screen(SaveScreen(f"AAR created: {file_name}"))
		elif event.button.id == "clear_aar_button":
			self.clear_aar_form()
		elif event.button.id == "save_vuln_button":
			file_name = self.collect_vuln_data()
			self.push_screen(SaveScreen(f"Vulnerability Assessment created: {file_name}"))
		elif event.button.id == "clear_vuln_button":
			self.clear_vuln_form()


class SaveScreen(Screen):
	def __init__(self, message="File has been created!"):
		super().__init__()
		self.message = message

	def compose(self) -> ComposeResult:
		yield Grid(
			Label(f"{self.message}\nLook at {REPORTS_DIR}"),
			Button("Continue", id="continue_button"),
		)

	def on_button_pressed(self, event: Button.Pressed) -> None:
		if event.button.id == "continue_button":
			self.app.pop_screen()


if __name__ == "__main__":
	app = ReporterApp()
	app.run()