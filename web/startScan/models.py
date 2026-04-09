from urllib.parse import urlparse
from django.apps import apps
from django.contrib.auth.models import User
from django.contrib.postgres.fields import ArrayField
from django.db import models
from django.utils import timezone
from reNgine.definitions import (CELERY_TASK_STATUSES,
								 NUCLEI_REVERSE_SEVERITY_MAP)
from reNgine.utilities import *
from scanEngine.models import EngineType
from targetApp.models import Domain


class hybrid_property:
	def __init__(self, func):
		self.func = func
		self.name = func.__name__
		self.exp = None

	def __get__(self, instance, owner):
		if instance is None:
			return self
		return self.func(instance)

	def __set__(self, instance, value):
		pass

	def expression(self, exp):
		self.exp = exp
		return self


class ScanHistory(models.Model):
	id = models.AutoField(primary_key=True)
	start_scan_date = models.DateTimeField(default=timezone.now)
	scan_status = models.IntegerField(choices=CELERY_TASK_STATUSES, default=-1)
	results_dir = models.CharField(max_length=100, blank=True)
	domain = models.ForeignKey(Domain, on_delete=models.CASCADE)
	scan_type = models.ForeignKey(EngineType, on_delete=models.CASCADE)
	celery_ids = ArrayField(models.CharField(max_length=100), blank=True, default=list)
	tasks = ArrayField(models.CharField(max_length=200), null=True)
	stop_scan_date = models.DateTimeField(null=True, blank=True)
	used_gf_patterns = models.CharField(max_length=500, null=True, blank=True)
	error_message = models.CharField(max_length=300, blank=True, null=True)
	emails = models.ManyToManyField('Email', related_name='emails', blank=True)
	employees = models.ManyToManyField('Employee', related_name='employees', blank=True)
	buckets = models.ManyToManyField('S3Bucket', related_name='buckets', blank=True)
	dorks = models.ManyToManyField('Dork', related_name='dorks', blank=True)
	initiated_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='initiated_scans', blank=True, null=True)
	aborted_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='aborted_scans')
	# scan related configs, prefix config fields with cfg_
	cfg_out_of_scope_subdomains = ArrayField(
		models.CharField(max_length=200),
		blank=True,
		null=True,
		default=list
	)
	cfg_starting_point_path = models.CharField(max_length=200, blank=True, null=True)
	cfg_excluded_paths = ArrayField(
		models.CharField(max_length=200),
		blank=True,
		null=True,
		default=list
	)
	cfg_imported_subdomains = ArrayField(
		models.CharField(max_length=200),
		blank=True,
		null=True,
		default=list
	)
	cfg_proxy_mode = models.CharField(
		max_length=20,
		default='auto',
		choices=[('auto', 'Auto (use proxy if available)'), ('none', 'No proxy (direct connection)')],
		help_text='Whether to route scan traffic through a proxy.'
	)


	def __str__(self):
		return self.domain.name

	def get_subdomain_count(self):
		return Subdomain.objects.filter(scan_history__id=self.id).count()

	def get_subdomain_change_count(self):
		last_scan = (
			ScanHistory.objects
			.filter(id=self.id)
			.filter(tasks__overlap=['subdomain_discovery'])
			.order_by('-start_scan_date')
		)
		scanned_host_q1 = (
			Subdomain.objects
			.filter(target_domain__id=self.domain.id)
			.exclude(scan_history__id=last_scan[0].id)
			.values('name')
		)
		scanned_host_q2 = (
			Subdomain.objects
			.filter(scan_history__id=last_scan[0].id)
			.values('name')
		)
		new_subdomains = scanned_host_q2.difference(scanned_host_q1).count()
		removed_subdomains = scanned_host_q1.difference(scanned_host_q2).count()
		return [new_subdomains, removed_subdomains]


	def get_endpoint_count(self):
		return (
			EndPoint.objects
			.filter(scan_history__id=self.id)
			.count()
		)

	def get_vulnerability_count(self):
		return (
			Vulnerability.objects
			.filter(scan_history__id=self.id)
			.count()
		)

	def get_unknown_vulnerability_count(self):
		return (
			Vulnerability.objects
			.filter(scan_history__id=self.id)
			.filter(severity=-1)
			.count()
		)

	def get_info_vulnerability_count(self):
		return (
			Vulnerability.objects
			.filter(scan_history__id=self.id)
			.filter(severity=0)
			.count()
		)

	def get_low_vulnerability_count(self):
		return (
			Vulnerability.objects
			.filter(scan_history__id=self.id)
			.filter(severity=1)
			.count()
		)

	def get_medium_vulnerability_count(self):
		return (
			Vulnerability.objects
			.filter(scan_history__id=self.id)
			.filter(severity=2)
			.count()
		)

	def get_high_vulnerability_count(self):
		return (
			Vulnerability.objects
			.filter(scan_history__id=self.id)
			.filter(severity=3)
			.count()
		)

	def get_critical_vulnerability_count(self):
		return (
			Vulnerability.objects
			.filter(scan_history__id=self.id)
			.filter(severity=4)
			.count()
		)

	def get_progress(self):
		"""Calculate scan progress as percentage of completed activities vs total steps."""
		number_of_steps = len(self.tasks) if self.tasks else 0
		# MED-19 fix: Use .count() instead of len(.all()), and fix inverted formula
		steps_done = self.scanactivity_set.count()
		if steps_done and number_of_steps:
			return min(round((steps_done / number_of_steps) * 100, 2), 100.0)

	def get_completed_ago(self):
		if self.stop_scan_date:
			return self.get_time_ago(self.stop_scan_date)

	def get_total_scan_time_in_sec(self):
		if self.stop_scan_date:
			# MED-21 fix: Use .total_seconds() instead of .seconds to include days
			return int((self.stop_scan_date - self.start_scan_date).total_seconds())

	def get_elapsed_time(self):
		return self.get_time_ago(self.start_scan_date)

	def get_time_ago(self, time):
		duration = timezone.now() - time
		days, seconds = duration.days, duration.seconds
		hours = days * 24 + seconds // 3600
		minutes = (seconds % 3600) // 60
		seconds = seconds % 60
		if not hours and not minutes:
			return f'{seconds} seconds'
		elif not hours:
			return f'{minutes} minutes'
		elif not minutes:
			return f'{hours} hours'
		return f'{hours} hours {minutes} minutes'


class Subdomain(models.Model):
	# TODO: Add endpoint property instead of replicating endpoint fields here
	id = models.AutoField(primary_key=True)
	scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, null=True, blank=True)
	target_domain = models.ForeignKey(Domain, on_delete=models.CASCADE, null=True, blank=True)
	name = models.CharField(max_length=1000)
	is_imported_subdomain = models.BooleanField(default=False)
	is_important = models.BooleanField(default=False, null=True, blank=True)
	http_url = models.CharField(max_length=10000, null=True, blank=True)
	screenshot_path = models.CharField(max_length=1000, null=True, blank=True)
	http_header_path = models.CharField(max_length=1000, null=True, blank=True)
	discovered_date = models.DateTimeField(blank=True, null=True, default=timezone.now)
	cname = models.CharField(max_length=5000, blank=True, null=True)
	is_cdn = models.BooleanField(default=False, blank=True, null=True)
	cdn_name = models.CharField(max_length=200, blank=True, null=True)
	http_status = models.IntegerField(default=0)
	content_type = models.CharField(max_length=100, null=True, blank=True)
	response_time = models.FloatField(null=True, blank=True)
	webserver = models.CharField(max_length=1000, blank=True, null=True)
	content_length = models.IntegerField(default=0, blank=True, null=True)
	page_title = models.CharField(max_length=1000, blank=True, null=True)
	technologies = models.ManyToManyField('Technology', related_name='technologies', blank=True)
	ip_addresses = models.ManyToManyField('IpAddress', related_name='ip_addresses', blank=True)
	directories = models.ManyToManyField('DirectoryScan', related_name='directories', blank=True)
	waf = models.ManyToManyField('Waf', related_name='waf', blank=True)
	attack_surface = models.TextField(null=True, blank=True)


	def __str__(self):
		return str(self.name)

	@property
	def get_endpoint_count(self):
		endpoints = EndPoint.objects.filter(subdomain__name=self.name)
		if self.scan_history:
			endpoints = endpoints.filter(scan_history=self.scan_history)
		return endpoints.count()

	@property
	def get_info_count(self):
		return (
			self.get_vulnerabilities
			.filter(severity=0)
			.count()
		)

	@property
	def get_low_count(self):
		return (
			self.get_vulnerabilities
			.filter(severity=1)
			.count()
		)

	@property
	def get_medium_count(self):
		return (
			self.get_vulnerabilities
			.filter(severity=2)
			.count()
		)

	@property
	def get_high_count(self):
		return (
			self.get_vulnerabilities
			.filter(severity=3)
			.count()
		)

	@property
	def get_critical_count(self):
		return (
			self.get_vulnerabilities
			.filter(severity=4)
			.count()
		)

	@property
	def get_total_vulnerability_count(self):
		return self.get_vulnerabilities.count()

	@property
	def get_vulnerabilities(self):
		vulns = Vulnerability.objects.filter(subdomain__name=self.name)
		if self.scan_history:
			vulns = vulns.filter(scan_history=self.scan_history)
		return vulns

	@property
	def get_vulnerabilities_without_info(self):
		vulns = Vulnerability.objects.filter(subdomain__name=self.name).exclude(severity=0)
		if self.scan_history:
			vulns = vulns.filter(scan_history=self.scan_history)
		return vulns

	@property
	def get_directories_count(self):
		subdomains = (
			Subdomain.objects
			.filter(id=self.id)
		)
		dirscan = (
			DirectoryScan.objects
			.filter(directories__in=subdomains)
		)
		return (
			DirectoryFile.objects
			.filter(directory_files__in=dirscan)
			.distinct()
			.count()
		)

	@property
	def get_todos(self):
		TodoNote = apps.get_model('recon_note', 'TodoNote')
		notes = TodoNote.objects
		if self.scan_history:
			notes = notes.filter(scan_history=self.scan_history)
		notes = notes.filter(subdomain__id=self.id)
		return notes.values()

	@property
	def get_subscan_count(self):
		return (
			SubScan.objects
			.filter(subdomain__id=self.id)
			.distinct()
			.count()
		)


class SubScan(models.Model):
	id = models.AutoField(primary_key=True)
	type = models.CharField(max_length=100, blank=True, null=True)
	start_scan_date = models.DateTimeField(default=timezone.now)
	status = models.IntegerField()
	celery_ids = ArrayField(models.CharField(max_length=100), blank=True, default=list)
	scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE)
	subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE)
	stop_scan_date = models.DateTimeField(null=True, blank=True)
	error_message = models.CharField(max_length=300, blank=True, null=True)
	engine = models.ForeignKey(EngineType, on_delete=models.CASCADE, blank=True, null=True)
	subdomain_subscan_ids = models.ManyToManyField('Subdomain', related_name='subdomain_subscan_ids', blank=True)

	def get_completed_ago(self):
		if self.stop_scan_date:
			return get_time_taken(timezone.now(), self.stop_scan_date)

	def get_total_time_taken(self):
		if self.stop_scan_date:
			return get_time_taken(self.stop_scan_date, self.start_scan_date)

	def get_elapsed_time(self):
		return get_time_taken(timezone.now(), self.start_scan_date)

	def get_task_name_str(self):
		taskmap = {
			'subdomain_discovery': 'Subdomain discovery',
			'dir_file_fuzz': 'Directory and File fuzzing',
			'port_scan': 'Port Scan',
			'fetch_url': 'Fetch URLs',
			'vulnerability_scan': 'Vulnerability Scan',
			'screenshot': 'Screenshot',
			'waf_detection': 'Waf Detection',
			'osint': 'Open-Source Intelligence'
		}
		return taskmap.get(self.type, 'Unknown')

class EndPoint(models.Model):
	id = models.AutoField(primary_key=True)
	scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, null=True, blank=True)
	target_domain = models.ForeignKey(
		Domain, on_delete=models.CASCADE, null=True, blank=True)
	subdomain = models.ForeignKey(
		Subdomain,
		on_delete=models.CASCADE,
		null=True,
		blank=True)
	source = models.CharField(max_length=200, null=True, blank=True)
	http_url = models.CharField(max_length=30000)
	content_length = models.IntegerField(default=0, null=True, blank=True)
	page_title = models.CharField(max_length=30000, null=True, blank=True)
	http_status = models.IntegerField(default=0, null=True, blank=True)
	content_type = models.CharField(max_length=100, null=True, blank=True)
	discovered_date = models.DateTimeField(blank=True, null=True, default=timezone.now)
	response_time = models.FloatField(null=True, blank=True)
	webserver = models.CharField(max_length=1000, blank=True, null=True)
	is_default = models.BooleanField(null=True, blank=True, default=False)
	matched_gf_patterns = models.CharField(max_length=10000, null=True, blank=True)
	techs = models.ManyToManyField('Technology', related_name='techs', blank=True)
	# used for subscans
	endpoint_subscan_ids = models.ManyToManyField('SubScan', related_name='endpoint_subscan_ids', blank=True)

	def __str__(self):
		return self.http_url

	@hybrid_property
	def is_alive(self):
		return self.http_status and (0 < self.http_status < 500) and self.http_status != 404


class VulnerabilityTags(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=100)

	def __str__(self):
		return self.name


class VulnerabilityReference(models.Model):
	id = models.AutoField(primary_key=True)
	url = models.CharField(max_length=5000)

	def __str__(self):
		return self.url


class CveId(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=100)

	def __str__(self):
		return self.name


class CweId(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=100)

	def __str__(self):
		return self.name


class GPTVulnerabilityReport(models.Model):
	url_path = models.CharField(max_length=2000)
	title = models.CharField(max_length=2500)
	description = models.TextField(null=True, blank=True)
	impact = models.TextField(null=True, blank=True)
	remediation = models.TextField(null=True, blank=True)
	references = models.ManyToManyField('VulnerabilityReference', related_name='report_reference', blank=True)

	def __str__(self):
		return self.title


class Vulnerability(models.Model):
	id = models.AutoField(primary_key=True)
	scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, null=True, blank=True)
	source = models.CharField(max_length=200, null=True, blank=True)
	subdomain = models.ForeignKey(
		Subdomain,
		on_delete=models.CASCADE,
		null=True,
		blank=True)
	endpoint = models.ForeignKey(
		EndPoint,
		on_delete=models.CASCADE,
		blank=True,
		null=True)
	target_domain = models.ForeignKey(
		Domain, on_delete=models.CASCADE, null=True, blank=True)
	template = models.CharField(max_length=100, null=True, blank=True)
	template_url = models.CharField(max_length=2500, null=True, blank=True)
	template_id = models.CharField(max_length=200, null=True, blank=True)
	matcher_name = models.CharField(max_length=500, null=True, blank=True)
	name = models.CharField(max_length=2500)
	severity = models.IntegerField()
	description = models.TextField(null=True, blank=True)
	impact = models.TextField(null=True, blank=True)
	remediation = models.TextField(null=True, blank=True)

	extracted_results = ArrayField(
		models.CharField(max_length=5000), blank=True, null=True
	)

	tags = models.ManyToManyField('VulnerabilityTags', related_name='vuln_tags', blank=True)
	references = models.ManyToManyField('VulnerabilityReference', related_name='vuln_reference', blank=True)
	cve_ids = models.ManyToManyField('CveId', related_name='cve_ids', blank=True)
	cwe_ids = models.ManyToManyField('CweId', related_name='cwe_ids', blank=True)

	cvss_metrics = models.CharField(max_length=500, null=True, blank=True)
	cvss_score = models.FloatField(null=True, blank=True, default=None)
	curl_command = models.CharField(max_length=15000, null=True, blank=True)
	type = models.CharField(max_length=100, null=True, blank=True)
	http_url = models.CharField(max_length=10000, null=True)
	discovered_date = models.DateTimeField(null=True, default=timezone.now)
	open_status = models.BooleanField(null=True, blank=True, default=True)
	hackerone_report_id = models.CharField(max_length=50, null=True, blank=True)
	request = models.TextField(blank=True, null=True)
	response = models.TextField(blank=True, null=True)
	is_gpt_used = models.BooleanField(null=True, blank=True, default=False)
	# used for subscans
	vuln_subscan_ids = models.ManyToManyField('SubScan', related_name='vuln_subscan_ids', blank=True)

	def __str__(self):
		cve_str = ', '.join(f'`{cve.name}`' for cve in self.cve_ids.all())
		severity = NUCLEI_REVERSE_SEVERITY_MAP[self.severity]
		return f'{self.http_url} | `{severity.upper()}` | `{self.name}` | `{cve_str}`'

	def get_severity(self):
		return self.severity

	def get_cve_str(self):
		return ', '.join(f'`{cve.name}`' for cve in self.cve_ids.all())

	def get_cwe_str(self):
		return ', '.join(f'`{cwe.name}`' for cwe in self.cwe_ids.all())

	def get_tags_str(self):
		return ', '.join(f'`{tag.name}`' for tag in self.tags.all())

	def get_refs_str(self):
		return '•' + '\n• '.join(f'`{ref.url}`' for ref in self.references.all())

	def get_path(self):
		return urlparse(self.http_url).path


class ScanActivity(models.Model):
	id = models.AutoField(primary_key=True)
	scan_of = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, blank=True, null=True)
	title = models.CharField(max_length=1000)
	name = models.CharField(max_length=1000)
	time = models.DateTimeField()
	status = models.IntegerField()
	error_message = models.CharField(max_length=300, blank=True, null=True)
	traceback = models.TextField(blank=True, null=True)
	celery_id = models.CharField(max_length=100, blank=True, null=True)

	def __str__(self):
		return str(self.title)


class Command(models.Model):
	id = models.AutoField(primary_key=True)
	scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, blank=True, null=True)
	activity = models.ForeignKey(ScanActivity, on_delete=models.CASCADE, blank=True, null=True)
	command = models.TextField(blank=True, null=True)
	return_code = models.IntegerField(blank=True, null=True)
	output = models.TextField(blank=True, null=True)
	time = models.DateTimeField()

	def __str__(self):
		return str(self.command)


class Waf(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=500)
	manufacturer = models.CharField(max_length=500, blank=True, null=True)

	def __str__(self):
		return str(self.name)


class Technology(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=500, blank=True, null=True)

	def __str__(self):
		return str(self.name)


class CountryISO(models.Model):
	id = models.AutoField(primary_key=True)
	iso = models.CharField(max_length=10, blank=True)
	name = models.CharField(max_length=100, blank=True)

	def __str__(self):
		return str(self.name)


class IpAddress(models.Model):
	id = models.AutoField(primary_key=True)
	address = models.CharField(max_length=100, blank=True, null=True)
	is_cdn = models.BooleanField(default=False)
	ports = models.ManyToManyField('Port', related_name='ports')
	geo_iso = models.ForeignKey(
		CountryISO, on_delete=models.CASCADE, null=True, blank=True)
	version = models.IntegerField(blank=True, null=True)
	is_private = models.BooleanField(default=False)
	reverse_pointer = models.CharField(max_length=100, blank=True, null=True)
	# this is used for querying which ip was discovered during subcan
	ip_subscan_ids = models.ManyToManyField('SubScan', related_name='ip_subscan_ids')

	def __str__(self):
		return str(self.address)


class Port(models.Model):
	id = models.AutoField(primary_key=True)
	number = models.IntegerField(default=0)
	service_name = models.CharField(max_length=100, blank=True, null=True)
	description = models.CharField(max_length=1000, blank=True, null=True)
	is_uncommon = models.BooleanField(default=False)

	def __str__(self):
		return str(self.service_name)


class DirectoryFile(models.Model):
	id = models.AutoField(primary_key=True)
	length = models.IntegerField(default=0)
	lines = models.IntegerField(default=0)
	http_status = models.IntegerField(default=0)
	words = models.IntegerField(default=0)
	name = models.CharField(max_length=500, blank=True, null=True)
	url = models.CharField(max_length=5000, blank=True, null=True)
	content_type = models.CharField(max_length=100, blank=True, null=True)

	def __str__(self):
		return str(self.name)


class DirectoryScan(models.Model):
	id = models.AutoField(primary_key=True)
	command_line = models.CharField(max_length=5000, blank=True, null=True)
	directory_files = models.ManyToManyField('DirectoryFile', related_name='directory_files', blank=True)
	scanned_date = models.DateTimeField(null=True)
	# this is used for querying which ip was discovered during subcan
	dir_subscan_ids = models.ManyToManyField('SubScan', related_name='dir_subscan_ids', blank=True)


class MetaFinderDocument(models.Model):
	id = models.AutoField(primary_key=True)
	scan_history = models.ForeignKey(ScanHistory, on_delete=models.CASCADE, null=True, blank=True)
	target_domain = models.ForeignKey(
		Domain, on_delete=models.CASCADE, null=True, blank=True)
	subdomain = models.ForeignKey(
		Subdomain,
		on_delete=models.CASCADE,
		null=True,
		blank=True)
	doc_name = models.CharField(max_length=1000, null=True, blank=True)
	url = models.CharField(max_length=10000, null=True, blank=True)
	title = models.CharField(max_length=1000, null=True, blank=True)
	author = models.CharField(max_length=1000, null=True, blank=True)
	producer = models.CharField(max_length=1000, null=True, blank=True)
	creator = models.CharField(max_length=1000, null=True, blank=True)
	os = models.CharField(max_length=1000, null=True, blank=True)
	http_status = models.IntegerField(default=0, null=True, blank=True)
	creation_date = models.CharField(max_length=1000, blank=True, null=True)
	modified_date = models.CharField(max_length=1000, blank=True, null=True)


class Email(models.Model):
	id = models.AutoField(primary_key=True)
	address = models.CharField(max_length=200, blank=True, null=True)
	password = models.CharField(max_length=200, blank=True, null=True)

	def __str__(self):
		return self.address or f'Email #{self.id}'

	class Meta:
		verbose_name = 'Email'
		verbose_name_plural = 'Emails'

	@property
	def has_credentials(self):
		"""Return whether credentials were found, without exposing the password."""
		return bool(self.password)

	def get_masked_password(self):
		"""Return masked password for safe display."""
		if not self.password:
			return None
		if len(self.password) > 4:
			return f'****...{self.password[-4:]}'
		return '****'

class Employee(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=1000, null=True, blank=True)
	designation = models.CharField(max_length=1000, null=True, blank=True)


class Dork(models.Model):
	id = models.AutoField(primary_key=True)
	type = models.CharField(max_length=500, null=True, blank=True)
	url = models.CharField(max_length=10000, null=True, blank=True)


class S3Bucket(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=500, null=True, blank=True)
	region = models.CharField(max_length=500, null=True, blank=True)
	provider = models.CharField(max_length=100, null=True, blank=True)
	owner_id = models.CharField(max_length=250, null=True, blank=True)
	owner_display_name = models.CharField(max_length=250, null=True, blank=True)
	perm_auth_users_read = models.IntegerField(default=0)
	perm_auth_users_write = models.IntegerField(default=0)
	perm_auth_users_read_acl = models.IntegerField(default=0)
	perm_auth_users_write_acl = models.IntegerField(default=0)
	perm_auth_users_full_control = models.IntegerField(default=0)
	perm_all_users_read = models.IntegerField(default=0)
	perm_all_users_write = models.IntegerField(default=0)
	perm_all_users_read_acl = models.IntegerField(default=0)
	perm_all_users_write_acl = models.IntegerField(default=0)
	perm_all_users_full_control = models.IntegerField(default=0)
	num_objects = models.IntegerField(default=0)
	size = models.IntegerField(default=0)


###############################################################################
# HUMINT — Human Intelligence Models
###############################################################################

class HumintEmployeeProfile(models.Model):
	"""Extended employee profile enriched from multiple OSINT sources."""
	id = models.AutoField(primary_key=True)
	scan_history = models.ForeignKey(
		ScanHistory, on_delete=models.CASCADE, null=True, blank=True,
		related_name='humint_employees')
	target_domain = models.ForeignKey(
		Domain, on_delete=models.CASCADE, null=True, blank=True)

	# Identity
	full_name = models.CharField(max_length=500, null=True, blank=True)
	first_name = models.CharField(max_length=200, null=True, blank=True)
	last_name = models.CharField(max_length=200, null=True, blank=True)
	designation = models.CharField(max_length=500, null=True, blank=True)
	department = models.CharField(max_length=200, null=True, blank=True)
	location = models.CharField(max_length=200, null=True, blank=True)

	# Contact vectors
	email = models.CharField(max_length=300, null=True, blank=True)
	email_pattern = models.CharField(max_length=100, null=True, blank=True)  # e.g. {f}{last}@company.com

	# Social presence
	linkedin_url = models.URLField(max_length=500, null=True, blank=True)
	github_url = models.URLField(max_length=500, null=True, blank=True)
	twitter_url = models.URLField(max_length=500, null=True, blank=True)

	# Source
	source = models.CharField(max_length=100, null=True, blank=True)  # linkedin/github/harvester
	discovered_date = models.DateTimeField(auto_now_add=True)

	class Meta:
		verbose_name = 'HUMINT Employee Profile'
		unique_together = [('scan_history', 'full_name', 'email')]

	def __str__(self):
		return f'{self.full_name} [{self.designation}] — {self.source}'


class HumintGithubRecon(models.Model):
	"""GitHub org/repo recon results."""
	id = models.AutoField(primary_key=True)
	scan_history = models.ForeignKey(
		ScanHistory, on_delete=models.CASCADE, null=True, blank=True,
		related_name='humint_github_recon')
	target_domain = models.ForeignKey(
		Domain, on_delete=models.CASCADE, null=True, blank=True)

	# Org info
	org_login = models.CharField(max_length=200, null=True, blank=True)
	org_name = models.CharField(max_length=500, null=True, blank=True)
	org_description = models.TextField(null=True, blank=True)
	org_blog = models.URLField(max_length=500, null=True, blank=True)
	org_location = models.CharField(max_length=200, null=True, blank=True)
	public_repos = models.IntegerField(default=0)
	public_members = models.IntegerField(default=0)

	# Findings summary (stored as JSON text)
	members_json = models.TextField(null=True, blank=True)    # list of usernames
	repos_json = models.TextField(null=True, blank=True)      # list of repo names
	emails_found = models.TextField(null=True, blank=True)    # emails found in commits
	secrets_found = models.BooleanField(default=False)
	secrets_json = models.TextField(null=True, blank=True)    # suspected leaked secrets

	discovered_date = models.DateTimeField(auto_now_add=True)

	class Meta:
		verbose_name = 'HUMINT GitHub Recon'

	def __str__(self):
		return f'GitHub recon: {self.org_login or self.target_domain}'


class HumintJobPosting(models.Model):
	"""Job postings that reveal internal tech stack / infrastructure."""
	id = models.AutoField(primary_key=True)
	scan_history = models.ForeignKey(
		ScanHistory, on_delete=models.CASCADE, null=True, blank=True,
		related_name='humint_job_postings')
	target_domain = models.ForeignKey(
		Domain, on_delete=models.CASCADE, null=True, blank=True)

	title = models.CharField(max_length=500, null=True, blank=True)
	company = models.CharField(max_length=300, null=True, blank=True)
	url = models.CharField(max_length=1000, null=True, blank=True)
	source = models.CharField(max_length=100, null=True, blank=True)  # linkedin/glassdoor/indeed

	# Extracted tech stack signals
	technologies = ArrayField(
		models.CharField(max_length=200), blank=True, default=list)
	raw_description = models.TextField(null=True, blank=True)

	discovered_date = models.DateTimeField(auto_now_add=True)

	class Meta:
		verbose_name = 'HUMINT Job Posting'

	def __str__(self):
		return f'{self.title} @ {self.company} ({self.source})'


###############################################################################
# SIGINT — Signals Intelligence Models
###############################################################################

class SigintAsnRecord(models.Model):
	"""ASN/BGP ownership data for the target organization."""
	id = models.AutoField(primary_key=True)
	scan_history = models.ForeignKey(
		ScanHistory, on_delete=models.CASCADE, null=True, blank=True,
		related_name='sigint_asn_records')
	target_domain = models.ForeignKey(
		Domain, on_delete=models.CASCADE, null=True, blank=True)

	asn = models.CharField(max_length=30, null=True, blank=True)        # e.g. AS12345
	org_name = models.CharField(max_length=300, null=True, blank=True)
	country = models.CharField(max_length=100, null=True, blank=True)
	registry = models.CharField(max_length=50, null=True, blank=True)   # arin/ripe/apnic/lacnic/afrinic
	cidr_ranges = ArrayField(
		models.CharField(max_length=50), blank=True, default=list)
	ip_count = models.IntegerField(default=0)
	discovered_date = models.DateTimeField(auto_now_add=True)

	class Meta:
		verbose_name = 'SIGINT ASN Record'

	def __str__(self):
		return f'{self.asn} — {self.org_name}'


class SigintEmailSecurity(models.Model):
	"""Email security posture analysis (SPF, DKIM, DMARC)."""
	id = models.AutoField(primary_key=True)
	scan_history = models.ForeignKey(
		ScanHistory, on_delete=models.CASCADE, null=True, blank=True,
		related_name='sigint_email_security')
	target_domain = models.ForeignKey(
		Domain, on_delete=models.CASCADE, null=True, blank=True)
	domain_checked = models.CharField(max_length=500, null=True, blank=True)

	# SPF
	spf_record = models.TextField(null=True, blank=True)
	spf_valid = models.BooleanField(null=True, blank=True)
	spf_policy = models.CharField(max_length=20, null=True, blank=True)  # pass/soft/none/fail

	# DMARC
	dmarc_record = models.TextField(null=True, blank=True)
	dmarc_valid = models.BooleanField(null=True, blank=True)
	dmarc_policy = models.CharField(max_length=20, null=True, blank=True)  # none/quarantine/reject
	dmarc_pct = models.IntegerField(null=True, blank=True)

	# DKIM selectors discovered
	dkim_selectors = ArrayField(
		models.CharField(max_length=100), blank=True, default=list)
	dkim_records = models.TextField(null=True, blank=True)  # JSON of selector→record

	# Mail exchange infrastructure
	mx_records = models.TextField(null=True, blank=True)   # JSON list
	mail_provider = models.CharField(max_length=200, null=True, blank=True)  # Google/Microsoft/etc.

	# Risk assessment
	spoofing_risk = models.CharField(max_length=20, null=True, blank=True)  # high/medium/low
	risk_reasons = models.TextField(null=True, blank=True)

	discovered_date = models.DateTimeField(auto_now_add=True)

	class Meta:
		verbose_name = 'SIGINT Email Security'

	def __str__(self):
		return f'Email security: {self.domain_checked} [SPF:{self.spf_policy} DMARC:{self.dmarc_policy}]'


class SigintIntelligenceRecord(models.Model):
	"""Shodan / Censys passive intelligence on target IPs."""
	id = models.AutoField(primary_key=True)
	scan_history = models.ForeignKey(
		ScanHistory, on_delete=models.CASCADE, null=True, blank=True,
		related_name='sigint_intel_records')
	target_domain = models.ForeignKey(
		Domain, on_delete=models.CASCADE, null=True, blank=True)

	source = models.CharField(max_length=30, null=True, blank=True)  # shodan/censys
	ip_address = models.CharField(max_length=100, null=True, blank=True)
	hostname = models.CharField(max_length=500, null=True, blank=True)
	org = models.CharField(max_length=300, null=True, blank=True)
	isp = models.CharField(max_length=300, null=True, blank=True)
	country = models.CharField(max_length=100, null=True, blank=True)
	city = models.CharField(max_length=100, null=True, blank=True)
	asn = models.CharField(max_length=30, null=True, blank=True)
	os = models.CharField(max_length=200, null=True, blank=True)
	last_update = models.CharField(max_length=50, null=True, blank=True)

	# Exposed services
	open_ports = ArrayField(
		models.IntegerField(), blank=True, default=list)
	services_json = models.TextField(null=True, blank=True)   # JSON: port→service detail
	vulns_json = models.TextField(null=True, blank=True)      # CVEs from Shodan

	# Threat intel
	tags = ArrayField(
		models.CharField(max_length=100), blank=True, default=list)  # honeypot/tor/vpn/cdn
	is_cloud = models.BooleanField(default=False)

	discovered_date = models.DateTimeField(auto_now_add=True)

	class Meta:
		verbose_name = 'SIGINT Intelligence Record'

	def __str__(self):
		return f'{self.source.upper()} {self.ip_address}: {self.org}'


class SigintCertificateRecord(models.Model):
	"""Deep SSL/TLS certificate analysis from CT logs."""
	id = models.AutoField(primary_key=True)
	scan_history = models.ForeignKey(
		ScanHistory, on_delete=models.CASCADE, null=True, blank=True,
		related_name='sigint_cert_records')
	target_domain = models.ForeignKey(
		Domain, on_delete=models.CASCADE, null=True, blank=True)

	common_name = models.CharField(max_length=500, null=True, blank=True)
	issuer = models.CharField(max_length=500, null=True, blank=True)
	issuer_org = models.CharField(max_length=300, null=True, blank=True)
	san_domains = ArrayField(
		models.CharField(max_length=500), blank=True, default=list)

	not_before = models.DateTimeField(null=True, blank=True)
	not_after = models.DateTimeField(null=True, blank=True)
	is_expired = models.BooleanField(default=False)
	days_to_expiry = models.IntegerField(null=True, blank=True)

	cert_fingerprint = models.CharField(max_length=200, null=True, blank=True)
	serial_number = models.CharField(max_length=200, null=True, blank=True)
	key_algorithm = models.CharField(max_length=50, null=True, blank=True)  # RSA/EC
	key_bits = models.IntegerField(null=True, blank=True)

	# Certificate chains / anomalies
	is_self_signed = models.BooleanField(default=False)
	is_wildcard = models.BooleanField(default=False)
	uses_deprecated_algo = models.BooleanField(default=False)  # SHA1/MD5

	source_host = models.CharField(max_length=500, null=True, blank=True)
	source_port = models.IntegerField(default=443)
	discovered_date = models.DateTimeField(auto_now_add=True)

	class Meta:
		verbose_name = 'SIGINT Certificate Record'

	def __str__(self):
		return f'Cert: {self.common_name} (expires {self.not_after})'