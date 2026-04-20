import csv
import json
import os
import pprint
import subprocess
import random
import time
import validators
import xmltodict
import yaml
import tldextract
import concurrent.futures
import base64

from datetime import datetime
from urllib.parse import urlparse
from api.serializers import SubdomainSerializer
from celery import chain, chord, group
from celery.exceptions import ChordError
from celery.result import allow_join_result
from celery.utils.log import get_task_logger
from django.db.models import Count
from django.db import transaction
from dotted_dict import DottedDict
from django.utils import timezone
from django.shortcuts import get_object_or_404
from pycvesearch import CVESearch
from metafinder.extractor import extract_metadata_from_google_search

from paraKang.celery import app
from paraKang.celery_custom_task import ParaKangTask
from paraKang.common_func import *
from paraKang.definitions import *
from paraKang.settings import *
from paraKang.llm import *
from paraKang.utilities import *
from paraKang.security import (
	validate_domain, sanitize_domain, validate_url,
	sanitize_shell_arg, is_safe_path,
)
from dashboard.models import OllamaSettings
from scanEngine.models import (EngineType, InstalledExternalTool, Notification, Proxy)
from startScan.models import *
from startScan.models import EndPoint, Subdomain, Vulnerability
from targetApp.models import Domain

"""
Celery tasks.
"""

logger = get_task_logger(__name__)

# Sentinel returned by get_and_save_dork_results() when Google blocks the IP.
_GOOFUZZ_BLOCKED = object()


#----------------------#
# Scan / Subscan tasks #
#----------------------#


@app.task(name='initiate_scan', bind=False, queue='initiate_scan_queue')
def initiate_scan(
		scan_history_id,
		domain_id,
		engine_id=None,
		scan_type=LIVE_SCAN,
		results_dir=PARAKANG_RESULTS,
		imported_subdomains=None,
		out_of_scope_subdomains=None,
		initiated_by_id=None,
		starting_point_path='',
		excluded_paths=None,
		proxy_mode='auto',
	):
	"""Initiate a new scan.

	Args:
		scan_history_id (int): ScanHistory id.
		domain_id (int): Domain id.
		engine_id (int): Engine ID.
		scan_type (int): Scan type (periodic, live).
		results_dir (str): Results directory.
		imported_subdomains (list): Imported subdomains.
		out_of_scope_subdomains (list): Out-of-scope subdomains.
		starting_point_path (str): URL path. Default: '' Defined where to start the scan.
		initiated_by (int): User ID initiating the scan.
		excluded_paths (list): Excluded paths. Default: None, url paths to exclude from scan.
	"""
	logger.info('Initiating scan on celery')
	# LOW-02 fix: Initialize mutable defaults
	imported_subdomains = imported_subdomains or []
	out_of_scope_subdomains = out_of_scope_subdomains or []
	excluded_paths = excluded_paths or []
	scan = None
	try:
		# CRT-01 fix: Restructured scan initialization order.
		# For SCHEDULED_SCAN, create scan object first (engine_id is required).
		# For LIVE_SCAN, the scan history already exists.
		# In both cases, fetch scan BEFORE resolving engine_id to avoid NoneType crash.
		if scan_type == SCHEDULED_SCAN:
			if not engine_id:
				raise ValueError('engine_id is required for scheduled scans')
			scan_history_id = create_scan_object(
				host_id=domain_id,
				engine_id=engine_id,
				initiated_by_id=initiated_by_id,
			)

		# Fetch scan history - must happen BEFORE engine_id fallback resolution
		scan = ScanHistory.objects.get(pk=scan_history_id)

		# Resolve engine_id safely - scan is now guaranteed to be a valid object
		engine_id = engine_id or scan.scan_type.id
		engine = EngineType.objects.get(pk=engine_id)

		# Get YAML config
		config = yaml.safe_load(engine.yaml_configuration)
		enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
		gf_patterns = config.get(GF_PATTERNS, [])

		# Get domain and set last_scan_date
		domain = Domain.objects.get(pk=domain_id)
		domain.last_scan_date = timezone.now()
		domain.save()

		# Get path filter
		starting_point_path = starting_point_path.rstrip('/')

		scan.scan_status = RUNNING_TASK
		scan.scan_type = engine
		scan.celery_ids = [initiate_scan.request.id]
		scan.domain = domain
		scan.start_scan_date = timezone.now()
		scan.tasks = engine.tasks
		scan.results_dir = f'{results_dir}/{domain.name}_{scan.id}'
		add_gf_patterns = gf_patterns and 'fetch_url' in engine.tasks
		# add configs to scan object, cfg_ prefix is used to avoid conflicts with other scan object fields
		scan.cfg_starting_point_path = starting_point_path
		scan.cfg_excluded_paths = excluded_paths
		scan.cfg_out_of_scope_subdomains = out_of_scope_subdomains
		scan.cfg_imported_subdomains = imported_subdomains
		scan.cfg_proxy_mode = proxy_mode

		if add_gf_patterns:
			scan.used_gf_patterns = ','.join(gf_patterns)
		scan.save()

		# Create scan results dir (exist_ok=True so continuing an aborted scan
		# that already has a results dir does not raise FileExistsError)
		os.makedirs(scan.results_dir, exist_ok=True)

		# Build task context
		ctx = {
			'scan_history_id': scan_history_id,
			'engine_id': engine_id,
			'domain_id': domain.id,
			'results_dir': scan.results_dir,
			'starting_point_path': starting_point_path,
			'excluded_paths': excluded_paths,
			'yaml_configuration': config,
			'out_of_scope_subdomains': out_of_scope_subdomains,
			'proxy_mode': proxy_mode,
		}
		ctx_str = json.dumps(ctx, indent=2)

		# Send start notif
		logger.warning(f'Starting scan {scan_history_id} with context:\n{ctx_str}')
		send_scan_notif.delay(
			scan_history_id,
			subscan_id=None,
			engine_id=engine_id,
			status=CELERY_TASK_STATUS_MAP[scan.scan_status])

		# Save imported subdomains in DB
		save_imported_subdomains(imported_subdomains, ctx=ctx)

		# Create initial subdomain in DB: make a copy of domain as a subdomain so
		# that other tasks using subdomains can use it.
		subdomain_name = domain.name
		subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)

		# If enable_http_crawl is set, create an initial root HTTP endpoint so that
		# HTTP crawling can start somewhere
		http_url = f'{domain.name}{starting_point_path}' if starting_point_path else domain.name
		endpoint, _ = save_endpoint(
			http_url,
			ctx=ctx,
			crawl=enable_http_crawl,
			is_default=True,
			subdomain=subdomain
		)
		if endpoint and endpoint.is_alive:
			# TODO: add `root_endpoint` property to subdomain and simply do
			# subdomain.root_endpoint = endpoint instead
			logger.warning(f'Found subdomain root HTTP URL {endpoint.http_url}')
			subdomain.http_url = endpoint.http_url
			subdomain.http_status = endpoint.http_status
			subdomain.response_time = endpoint.response_time
			subdomain.page_title = endpoint.page_title
			subdomain.content_type = endpoint.content_type
			subdomain.content_length = endpoint.content_length
			for tech in endpoint.techs.all():
				subdomain.technologies.add(tech)
			subdomain.save()


		# Build Celery tasks, crafted according to the dependency graph below:
		# subdomain_discovery --> port_scan --> fetch_url --> dir_file_fuzz --> vulnerability_scan
		# osint								             	                   screenshot
		#						 	   		         	  	                   waf_detection
		#
		# dir_file_fuzz runs BEFORE vuln scan so that ffuf-discovered
		# endpoints are already in the DB when nuclei reads them.
		workflow = chain(
			group(
				subdomain_discovery.si(ctx=ctx, description='Subdomain discovery'),
				osint.si(ctx=ctx, description='OS Intelligence')
			),
			port_scan.si(ctx=ctx, description='Port scan'),
			fetch_url.si(ctx=ctx, description='Fetch URL'),
			dir_file_fuzz.si(ctx=ctx, description='Directories & files fuzz'),
			group(
				vulnerability_scan.si(ctx=ctx, description='Vulnerability scan'),
				screenshot.si(ctx=ctx, description='Screenshot'),
				waf_detection.si(ctx=ctx, description='WAF detection')
			)
		)

		# Build callback
		callback = report.si(ctx=ctx).set(link_error=[report.si(ctx=ctx)])

		# Run Celery chord
		logger.info(f'Running Celery workflow with {len(workflow.tasks) + 1} tasks')
		task = chain(workflow, callback).on_error(callback).delay()
		with transaction.atomic():
			scan_obj = ScanHistory.objects.select_for_update().get(id=scan.id)
			scan_obj.celery_ids.append(task.id)
			scan_obj.save(update_fields=['celery_ids'])

		return {
			'success': True,
			'task_id': task.id
		}
	except Exception as e:
		logger.exception(e)
		if scan:
			scan.scan_status = FAILED_TASK
			scan.error_message = str(e)
			scan.save()
		return {
			'success': False,
			'error': str(e)
		}


@app.task(name='initiate_subscan', bind=False, queue='subscan_queue')
def initiate_subscan(
		scan_history_id,
		subdomain_id,
		engine_id=None,
		scan_type=None,
		results_dir=PARAKANG_RESULTS,
		starting_point_path='',
		excluded_paths=[],
	):
	"""Initiate a new subscan.

	Args:
		scan_history_id (int): ScanHistory id.
		subdomain_id (int): Subdomain id.
		engine_id (int): Engine ID.
		scan_type (int): Scan type (periodic, live).
		results_dir (str): Results directory.
		starting_point_path (str): URL path. Default: ''
		excluded_paths (list): Excluded paths. Default: [], url paths to exclude from scan.
	"""

	# Get Subdomain, Domain and ScanHistory
	subdomain = Subdomain.objects.get(pk=subdomain_id)
	scan = ScanHistory.objects.get(pk=subdomain.scan_history.id)
	domain = Domain.objects.get(pk=subdomain.target_domain.id)

	# Get EngineType
	engine_id = engine_id or scan.scan_type.id
	engine = EngineType.objects.get(pk=engine_id)

	# Get YAML config
	config = yaml.safe_load(engine.yaml_configuration)
	enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)

	# Create scan activity of SubScan Model
	subscan = SubScan(
		start_scan_date=timezone.now(),
		celery_ids=[initiate_subscan.request.id],
		scan_history=scan,
		subdomain=subdomain,
		type=scan_type,
		status=RUNNING_TASK,
		engine=engine)
	subscan.save()

	# Get YAML configuration
	config = yaml.safe_load(engine.yaml_configuration)

	# Create results directory
	results_dir = f'{scan.results_dir}/subscans/{subscan.id}'
	os.makedirs(results_dir, exist_ok=True)

	# Run task — use explicit whitelist instead of globals() to prevent
	# arbitrary function execution (CRT-06 fix)
	SCAN_FUNCTIONS = {
		'subdomain_discovery': subdomain_discovery,
		'osint': osint,
		'port_scan': port_scan,
		'vulnerability_scan': vulnerability_scan,
		'dir_file_fuzz': dir_file_fuzz,
		'fetch_url': fetch_url,
		'dorking': dorking,
		'screenshot': screenshot,
		'waf_detection': waf_detection,
	}
	method = SCAN_FUNCTIONS.get(scan_type)
	if not method:
		logger.warning(f'Task {scan_type} is not supported by paraKang. Skipping')
		return
	scan.tasks.append(scan_type)
	scan.save()

	# Send start notif
	send_scan_notif.delay(
		scan.id,
		subscan_id=subscan.id,
		engine_id=engine_id,
		status='RUNNING')

	# Build context
	ctx = {
		'scan_history_id': scan.id,
		'subscan_id': subscan.id,
		'engine_id': engine_id,
		'domain_id': domain.id,
		'subdomain_id': subdomain.id,
		'yaml_configuration': config,
		'results_dir': results_dir,
		'starting_point_path': starting_point_path,
		'excluded_paths': excluded_paths,
	}

	# Create initial endpoints in DB: find domain HTTP endpoint so that HTTP
	# crawling can start somewhere
	base_url = f'{subdomain.name}{starting_point_path}' if starting_point_path else subdomain.name
	endpoint, _ = save_endpoint(
		base_url,
		crawl=enable_http_crawl,
		ctx=ctx,
		subdomain=subdomain)
	if endpoint and endpoint.is_alive:
		# TODO: add `root_endpoint` property to subdomain and simply do
		# subdomain.root_endpoint = endpoint instead
		logger.warning(f'Found subdomain root HTTP URL {endpoint.http_url}')
		subdomain.http_url = endpoint.http_url
		subdomain.http_status = endpoint.http_status
		subdomain.response_time = endpoint.response_time
		subdomain.page_title = endpoint.page_title
		subdomain.content_type = endpoint.content_type
		subdomain.content_length = endpoint.content_length
		for tech in endpoint.techs.all():
			subdomain.technologies.add(tech)
		subdomain.save()

	# Build header + callback
	workflow = method.si(ctx=ctx)
	callback = report.si(ctx=ctx).set(link_error=[report.si(ctx=ctx)])

	# Run Celery tasks
	task = chain(workflow, callback).on_error(callback).delay()
	with transaction.atomic():
		subscan_obj = SubScan.objects.select_for_update().get(id=subscan.id)
		subscan_obj.celery_ids.append(task.id)
		subscan_obj.save(update_fields=['celery_ids'])

	return {
		'success': True,
		'task_id': task.id
	}


@app.task(name='report', bind=False, queue='report_queue')
def report(ctx=None, description=None):
	"""Report task running after all other tasks.
	Mark ScanHistory or SubScan object as completed and update with final
	status, log run details and send notification.

	Args:
		ctx (dict, optional): Task context.
		description (str, optional): Task description shown in UI.
	"""
	if ctx is None:
		ctx = {}
	# Get objects
	subscan_id = ctx.get('subscan_id')
	scan_id = ctx.get('scan_history_id')
	engine_id = ctx.get('engine_id')
	scan = ScanHistory.objects.filter(pk=scan_id).first()
	subscan = SubScan.objects.filter(pk=subscan_id).first()

	# Get failed tasks
	tasks = ScanActivity.objects.filter(scan_history=scan).all()
	if subscan:
		tasks = tasks.filter(celery_id__in=subscan.celery_ids)

	# Mark any still-RUNNING tasks as FAILED — if report() is executing,
	# any task still in RUNNING state has crashed (worker killed, OOM, etc.)
	stuck_tasks = tasks.filter(status=RUNNING_TASK)
	if stuck_tasks.exists():
		logger.warning(f'report(): marking {stuck_tasks.count()} stuck RUNNING tasks as FAILED')
		stuck_tasks.update(status=FAILED_TASK)

	failed_tasks = tasks.filter(status=FAILED_TASK)

	# Get task status
	failed_count = failed_tasks.count()
	status = SUCCESS_TASK if failed_count == 0 else FAILED_TASK
	status_h = 'SUCCESS' if failed_count == 0 else 'FAILED'

	# Update scan / subscan status
	if subscan:
		subscan.stop_scan_date = timezone.now()
		subscan.status = status
		subscan.save()
	if scan:
		# If scan was already aborted by user, do NOT overwrite status or re-notify.
		# This prevents the ChordError-triggered report() from resetting an
		# ABORTED scan back to SUCCESS/FAILED and sending duplicate notifications.
		scan.refresh_from_db()
		if scan.scan_status == ABORTED_TASK:
			logger.info('report(): scan already aborted — skipping status update and notification')
			return
		if not subscan:
			scan.scan_status = status
		# Set stop_scan_date BEFORE send_scan_notif so duration calc in
		# get_scan_fields() doesn't subtract None - datetime
		scan.stop_scan_date = timezone.now()
		scan.save()

	# Send scan status notif
	send_scan_notif.delay(
		scan_history_id=scan_id,
		subscan_id=subscan_id,
		engine_id=engine_id,
		status=status_h)


#------------------------- #
# Tracked paraKang tasks    #
#--------------------------#

@app.task(name='subdomain_discovery', queue='main_scan_queue', base=ParaKangTask, bind=True)
def subdomain_discovery(
		self,
		host=None,
		ctx=None,
		description=None):
	"""Uses a set of tools (see SUBDOMAIN_SCAN_DEFAULT_TOOLS) to scan all
	subdomains associated with a domain.

	Args:
		host (str): Hostname to scan.

	Returns:
		subdomains (list): List of subdomain names.
	"""
	if not host:
		host = self.subdomain.name if self.subdomain else self.domain.name

	# CRT-01 fix: Validate domain name to prevent command injection
	if not validate_domain(host):
		logger.error(f'Invalid domain name rejected by security validation: {repr(host[:100])}')
		return

	if self.starting_point_path:
		logger.warning(f'Ignoring subdomains scan as an URL path filter was passed ({self.starting_point_path}).')
		return

	# Config
	config = self.yaml_configuration.get(SUBDOMAIN_DISCOVERY) or {}
	enable_http_crawl = config.get(ENABLE_HTTP_CRAWL) or self.yaml_configuration.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
	threads = config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
	timeout = config.get(TIMEOUT) or self.yaml_configuration.get(TIMEOUT, DEFAULT_HTTP_TIMEOUT)
	tools = config.get(USES_TOOLS, SUBDOMAIN_SCAN_DEFAULT_TOOLS)
	default_subdomain_tools = [tool.name.lower() for tool in InstalledExternalTool.objects.filter(is_default=True).filter(is_subdomain_gathering=True)]
	custom_subdomain_tools = [tool.name.lower() for tool in InstalledExternalTool.objects.filter(is_default=False).filter(is_subdomain_gathering=True)]
	send_subdomain_changes, send_interesting = False, False
	notif = Notification.objects.first()
	subdomain_scope_checker = SubdomainScopeChecker(self.out_of_scope_subdomains)
	if notif:
		send_subdomain_changes = notif.send_subdomain_changes_notif
		send_interesting = notif.send_interesting_notif

	# Gather tools to run for subdomain scan
	if ALL in tools:
		tools = SUBDOMAIN_SCAN_DEFAULT_TOOLS + custom_subdomain_tools
	tools = [t.lower() for t in tools]

	# Make exception for amass since tool name is amass, but command is amass-active/passive
	default_subdomain_tools.append('amass-passive')
	default_subdomain_tools.append('amass-active')

	# Run tools
	# CRT-01 fix: Use shlex.quote() on host to prevent shell injection
	import shlex
	safe_host = shlex.quote(host)
	for tool in tools:
		cmd = None
		cmd_env = None
		logger.info(f'Scanning subdomains for {host} with {tool}')
		proxy = get_random_proxy(proxy_mode=self.proxy_mode)
		if tool in default_subdomain_tools:
			if tool == 'amass-passive':
				use_amass_config = config.get(USE_AMASS_CONFIG, False)
				cmd = f'amass enum -passive -d {safe_host} -o {self.results_dir}/subdomains_amass.txt'
				cmd += ' -config /root/.config/amass.ini' if use_amass_config else ''

			elif tool == 'amass-active':
				use_amass_config = config.get(USE_AMASS_CONFIG, False)
				amass_wordlist_name = config.get(AMASS_WORDLIST, 'deepmagic.com-prefixes-top50000')
				wordlist_path = f'/usr/src/wordlist/{amass_wordlist_name}.txt'
				cmd = f'amass enum -active -d {safe_host} -o {self.results_dir}/subdomains_amass_active.txt'
				cmd += ' -config /root/.config/amass.ini' if use_amass_config else ''
				cmd += f' -brute -w {wordlist_path}'

			elif tool == 'sublist3r':
				cmd = f'python3 /usr/src/github/Sublist3r/sublist3r.py -d {safe_host} -t {threads} -o {self.results_dir}/subdomains_sublister.txt'

			elif tool == 'subfinder':
				cmd = f'subfinder -d {safe_host} -o {self.results_dir}/subdomains_subfinder.txt'
				use_subfinder_config = config.get(USE_SUBFINDER_CONFIG, False)
				cmd += ' -config /root/.config/subfinder/config.yaml' if use_subfinder_config else ''
				cmd += f' -proxy {proxy}' if proxy else ''
				cmd += f' -timeout {timeout}' if timeout else ''
				cmd += f' -t {threads}' if threads else ''
				cmd += f' -silent'

			elif tool == 'oneforall':
				cmd = f'python3 /usr/src/github/OneForAll/oneforall.py --target {safe_host} run'
				cmd_extract = f'cut -d\',\' -f6 /usr/src/github/OneForAll/results/{safe_host}.csv | tail -n +2 > {self.results_dir}/subdomains_oneforall.txt'
				cmd_rm = f'rm -rf /usr/src/github/OneForAll/results/{safe_host}.csv'
				cmd += f' && {cmd_extract} && {cmd_rm}'

			elif tool == 'ctfr':
				results_file = self.results_dir + '/subdomains_ctfr.txt'
				cmd = f'python3 /usr/src/github/ctfr/ctfr.py -d {safe_host} -o {results_file}'
				cmd_extract = f"cat {results_file} | sed 's/\*.//g' | tail -n +12 | uniq | sort > {results_file}"
				cmd += f' && {cmd_extract}'

			elif tool == 'tlsx':
				results_file = self.results_dir + '/subdomains_tlsx.txt'
				cmd = f'tlsx -san -cn -silent -ro -host {safe_host}'
				cmd += f" | sed -n '/^\([a-zA-Z0-9]\([-a-zA-Z0-9]*[a-zA-Z0-9]\)\?\.\)\+{safe_host}$/p' | uniq | sort"
				cmd += f' > {results_file}'

			elif tool == 'netlas':
				results_file = self.results_dir + '/subdomains_netlas.txt'
				cmd = f'netlas search -d domain -i domain domain:"*.{safe_host}" -f json'
				netlas_key = get_netlas_key()
				# MED-04 fix: Pass API key via environment variable instead of command line
				if netlas_key:
					cmd_env = {**os.environ, 'NETLAS_API_KEY': netlas_key}
				cmd_extract = f"grep -oE '([a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?\.)+{safe_host}'"
				cmd += f' | {cmd_extract} > {results_file}'

			elif tool == 'chaos':
				# we need to find api key if not ignore
				chaos_key = get_chaos_key()
				if not chaos_key:
					logger.error('Chaos API key not found. Skipping.')
					continue
				results_file = self.results_dir + '/subdomains_chaos.txt'
				cmd = f'chaos -d {safe_host} -silent -key {chaos_key} -o {results_file}'

		elif tool in custom_subdomain_tools:
			tool_query = InstalledExternalTool.objects.filter(name__icontains=tool.lower())
			if not tool_query.exists():
				logger.error(f'{tool} configuration does not exists. Skipping.')
				continue
			custom_tool = tool_query.first()
			cmd = custom_tool.subdomain_gathering_command
			if '{TARGET}' not in cmd:
				logger.error(f'Missing {{TARGET}} placeholders in {tool} configuration. Skipping.')
				continue
			if '{OUTPUT}' not in cmd:
				logger.error(f'Missing {{OUTPUT}} placeholders in {tool} configuration. Skipping.')
				continue

			
			cmd = cmd.replace('{TARGET}', safe_host)
			cmd = cmd.replace('{OUTPUT}', f'{self.results_dir}/subdomains_{tool}.txt')
			cmd = cmd.replace('{PATH}', custom_tool.github_clone_path) if '{PATH}' in cmd else cmd
		else:
			logger.warning(
				f'Subdomain discovery tool "{tool}" is not supported by paraKang. Skipping.')
			continue

		# Run tool
		try:
			run_command(
				cmd,
				shell=True,
				history_file=self.history_file,
				scan_id=self.scan_id,
				activity_id=self.activity_id,
				env=cmd_env)
		except Exception as e:
			logger.error(
				f'Subdomain discovery tool "{tool}" raised an exception')
			logger.exception(e)

	# Gather all the tools' results in one single file. Write subdomains into
	# separate files, and sort all subdomains.
	run_command(
		f'cat {self.results_dir}/subdomains_*.txt > {self.output_path}',
		shell=True,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id)
	run_command(
		f'sort -u {self.output_path} -o {self.output_path}',
		shell=True,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id)

	with open(self.output_path) as f:
		lines = f.readlines()

	# Parse the output_file file and store Subdomain and EndPoint objects found
	# in db.
	subdomain_count = 0
	subdomains = []
	urls = []
	for line in lines:
		subdomain_name = line.strip()
		valid_url = bool(validators.url(subdomain_name))
		valid_domain = (
			bool(validators.domain(subdomain_name)) or
			bool(validators.ipv4(subdomain_name)) or
			bool(validators.ipv6(subdomain_name)) or
			valid_url
		)
		if not valid_domain:
			logger.error(f'Subdomain {subdomain_name} is not a valid domain, IP or URL. Skipping.')
			continue

		if valid_url:
			subdomain_name = urlparse(subdomain_name).netloc

		if subdomain_scope_checker.is_out_of_scope(subdomain_name):
			logger.error(f'Subdomain {subdomain_name} is out of scope. Skipping.')
			continue

		# Add subdomain
		subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)
		if subdomain:
			subdomain_count += 1
			subdomains.append(subdomain)
			urls.append(subdomain.name)

	# Bulk crawl subdomains
	if enable_http_crawl:
		ctx['track'] = True
		http_crawl(urls, ctx=ctx, is_ran_from_subdomain_scan=True)

	# Find root subdomain endpoints
	for subdomain in subdomains:
		pass

	# Send notifications
	subdomains_str = '\n'.join([f'• `{subdomain.name}`' for subdomain in subdomains])
	self.notify(fields={
		'Subdomain count': len(subdomains),
		'Subdomains': subdomains_str,
	})
	if send_subdomain_changes and self.scan_id and self.domain_id:
		added = get_new_added_subdomain(self.scan_id, self.domain_id)
		removed = get_removed_subdomain(self.scan_id, self.domain_id)

		if added:
			subdomains_str = '\n'.join([f'• `{subdomain}`' for subdomain in added])
			self.notify(fields={'Added subdomains': subdomains_str})

		if removed:
			subdomains_str = '\n'.join([f'• `{subdomain}`' for subdomain in removed])
			self.notify(fields={'Removed subdomains': subdomains_str})

	if send_interesting and self.scan_id and self.domain_id:
		interesting_subdomains = get_interesting_subdomains(self.scan_id, self.domain_id)
		if interesting_subdomains:
			subdomains_str = '\n'.join([f'• `{subdomain}`' for subdomain in interesting_subdomains])
			self.notify(fields={'Interesting subdomains': subdomains_str})

	return SubdomainSerializer(subdomains, many=True).data


@app.task(name='osint', queue='main_scan_queue', base=ParaKangTask, bind=True)
def osint(self, host=None, ctx=None, description=None):
	"""Run Open-Source Intelligence tools on selected domain.

	Args:
		host (str): Hostname to scan.

	Returns:
		dict: Results from osint discovery and dorking.
	"""
	if ctx is None:
		ctx = {}
	config = self.yaml_configuration.get(OSINT) or OSINT_DEFAULT_CONFIG
	results = {}

	grouped_tasks = []

	if 'discover' in config:
		ctx['track'] = False
		# results = osint_discovery(host=host, ctx=ctx)
		_task = osint_discovery.si(
			config=config,
			host=self.scan.domain.name,
			scan_history_id=self.scan.id,
			activity_id=self.activity_id,
			results_dir=self.results_dir,
			ctx=ctx
		)
		grouped_tasks.append(_task)

	if OSINT_DORK in config or OSINT_CUSTOM_DORK in config:
		_task = dorking.si(
			config=config,
			host=self.scan.domain.name,
			scan_history_id=self.scan.id,
			results_dir=self.results_dir
		)
		grouped_tasks.append(_task)

	# HUMINT — Human Intelligence sub-tasks
	humint_config = config.get(OSINT_HUMINT, {})
	if humint_config:
		if humint_config.get(HUMINT_GITHUB_ORG, False):
			grouped_tasks.append(humint_github_recon.si(
				config=config,
				host=self.scan.domain.name,
				scan_history_id=self.scan.id,
				results_dir=self.results_dir,
				ctx=ctx,
			))
		if humint_config.get(HUMINT_LINKEDIN, False):
			grouped_tasks.append(humint_linkedin_recon.si(
				config=config,
				host=self.scan.domain.name,
				scan_history_id=self.scan.id,
				results_dir=self.results_dir,
				ctx=ctx,
			))
		if humint_config.get(HUMINT_JOB_POSTINGS, False):
			grouped_tasks.append(humint_job_postings.si(
				config=config,
				host=self.scan.domain.name,
				scan_history_id=self.scan.id,
				results_dir=self.results_dir,
				ctx=ctx,
			))

	# SIGINT — Signals Intelligence sub-tasks
	sigint_config = config.get(OSINT_SIGINT, {})
	if sigint_config:
		if sigint_config.get(SIGINT_ASN, False):
			grouped_tasks.append(sigint_asn_recon.si(
				config=config,
				host=self.scan.domain.name,
				scan_history_id=self.scan.id,
				results_dir=self.results_dir,
				ctx=ctx,
			))
		if sigint_config.get(SIGINT_EMAIL_SECURITY, False):
			grouped_tasks.append(sigint_email_security.si(
				config=config,
				host=self.scan.domain.name,
				scan_history_id=self.scan.id,
				results_dir=self.results_dir,
				ctx=ctx,
			))
		if sigint_config.get(SIGINT_PASSIVE_INTEL, False):
			grouped_tasks.append(sigint_passive_intel.si(
				config=config,
				host=self.scan.domain.name,
				scan_history_id=self.scan.id,
				results_dir=self.results_dir,
				ctx=ctx,
			))
		if sigint_config.get(SIGINT_CERT_ANALYSIS, False):
			grouped_tasks.append(sigint_cert_analysis.si(
				config=config,
				host=self.scan.domain.name,
				scan_history_id=self.scan.id,
				results_dir=self.results_dir,
				ctx=ctx,
			))

	celery_group = group(grouped_tasks)
	job = celery_group.apply_async()
	# MED-06 fix: Use allow_join_result() to permit .get() inside a Celery 5 task.
	# All sub-tasks run on separate queues so no deadlock risk.
	try:
		with allow_join_result():
			job.get(timeout=3600, interval=5)
	except ChordError as e:
		logger.warning(f'OSINT Tasks: chord aborted (scan likely stopped): {e}')
	except Exception as e:
		logger.error(f'OSINT Tasks error or timeout: {e}')

	logger.info('OSINT Tasks finished...')

	# with open(self.output_path, 'w') as f:
	# 	json.dump(results, f, indent=4)
	#
	# return results


@app.task(name='osint_discovery', queue='osint_discovery_queue', bind=False)
def osint_discovery(config, host, scan_history_id, activity_id, results_dir, ctx=None):
	if ctx is None:
		ctx = {}
	"""Run OSINT discovery.

	Args:
		config (dict): yaml_configuration
		host (str): target name
		scan_history_id (startScan.ScanHistory): Scan History ID
		results_dir (str): Path to store scan results

	Returns:
		dict: osint metadat and theHarvester and h8mail results.
	"""
	scan_history = ScanHistory.objects.get(pk=scan_history_id)
	osint_lookup = config.get(OSINT_DISCOVER, [])
	osint_intensity = config.get(INTENSITY, 'normal')
	documents_limit = config.get(OSINT_DOCUMENTS_LIMIT, 50)
	results = {}
	meta_info = []
	emails = []
	creds = []

	# Get and save meta info
	if 'metainfo' in osint_lookup:
		if osint_intensity == 'normal':
			meta_dict = DottedDict({
				'osint_target': host,
				'domain': host,
				'scan_id': scan_history_id,
				'documents_limit': documents_limit
			})
			try:
				meta_info.append(save_metadata_info(meta_dict))
			except Exception as e:
				logger.error(f'save_metadata_info failed for {host}: {e}')
				logger.warning('Continuing OSINT discovery — theHarvester/h8mail will still run.')

		# TODO: disabled for now
		# elif osint_intensity == 'deep':
		# 	subdomains = Subdomain.objects
		# 	if self.scan:
		# 		subdomains = subdomains.filter(scan_history=self.scan)
		# 	for subdomain in subdomains:
		# 		meta_dict = DottedDict({
		# 			'osint_target': subdomain.name,
		# 			'domain': self.domain,
		# 			'scan_id': self.scan_id,
		# 			'documents_limit': documents_limit
		# 		})
		# 		meta_info.append(save_metadata_info(meta_dict))

	# theHarvester must run BEFORE h8mail — theHarvester writes emails.txt which h8mail reads
	chain_tasks = []

	if 'employees' in osint_lookup:
		ctx['track'] = False
		_task = theHarvester.si(
			config=config,
			host=host,
			scan_history_id=scan_history_id,
			activity_id=activity_id,
			results_dir=results_dir,
			ctx=ctx
		)
		chain_tasks.append(_task)

	if 'emails' in osint_lookup:
		_task = h8mail.si(
			config=config,
			host=host,
			scan_history_id=scan_history_id,
			activity_id=activity_id,
			results_dir=results_dir,
			ctx=ctx
		)
		chain_tasks.append(_task)

	if chain_tasks:
		job = (chain(*chain_tasks) if len(chain_tasks) > 1 else chain_tasks[0]).apply_async()
		# MED-06 fix: Use allow_join_result() to permit .get() inside a Celery 5 task.
		# theHarvester runs on theHarvester_queue, h8mail on h8mail_queue — no deadlock risk.
		try:
			with allow_join_result():
				job.get(timeout=3600, interval=5)
		except ChordError as e:
			logger.warning(f'OSINT discovery: chord aborted (scan likely stopped): {e}')
		except Exception as e:
			logger.error(f'OSINT discovery tasks error or timeout: {e}')

	# results['emails'] = results.get('emails', []) + emails
	# results['creds'] = creds
	# results['meta_info'] = meta_info
	return results


###############################################################################
# HUMINT — Human Intelligence Tasks
###############################################################################

@app.task(name='humint_github_recon', bind=False, queue='osint_discovery_queue')
def humint_github_recon(config, host, scan_history_id, results_dir, ctx=None):
	"""Enumerate GitHub organization members, repos, and scan commit history
	for accidentally leaked email addresses and credential patterns.

	Uses only the unauthenticated GitHub API (/orgs/{org}/members,
	/orgs/{org}/repos, /repos/{owner}/{repo}/commits) when no token is set,
	falling back to the GITHUB_API_KEY setting when available.
	"""
	if ctx is None:
		ctx = {}
	import json as _json
	import re as _re
	import requests as _requests

	logger.info(f'HUMINT GitHub Recon starting for {host}')
	scan_history = ScanHistory.objects.get(pk=scan_history_id)
	domain = scan_history.domain
	history_file = f'{results_dir}/commands.txt'

	# Derive candidate org name from domain (e.g. "example.com" → "example")
	from tldextract import extract as _tld_extract
	tld = _tld_extract(host)
	org_candidate = tld.domain  # most likely GitHub org name

	# Build headers — use token if configured
	token = None
	try:
		from django.conf import settings as _dj_settings
		token = getattr(_dj_settings, 'GITHUB_API_KEY', None)
	except Exception:
		pass

	headers = {'Accept': 'application/vnd.github+json'}
	if token:
		headers['Authorization'] = f'token {token}'

	base_url = 'https://api.github.com'

	result = HumintGithubRecon(
		scan_history=scan_history,
		target_domain=domain,
		org_login=org_candidate,
	)

	# ── 1. Org lookup ──────────────────────────────────────────────────────
	try:
		r = _requests.get(f'{base_url}/orgs/{org_candidate}', headers=headers, timeout=15)
		if r.ok:
			org_data = r.json()
			result.org_name = org_data.get('name', org_candidate)
			result.org_description = org_data.get('description', '')[:500] if org_data.get('description') else ''
			result.org_blog = (org_data.get('blog') or '')[:500] or None
			result.org_location = (org_data.get('location') or '')[:200] or None
			result.public_repos = org_data.get('public_repos', 0)
			result.public_members = org_data.get('public_members', 0)
			logger.info(f'HUMINT GitHub: org {org_candidate} found — {result.public_repos} repos')
		else:
			logger.info(f'HUMINT GitHub: org {org_candidate} not found (HTTP {r.status_code})')
	except Exception as e:
		logger.warning(f'HUMINT GitHub: org lookup failed: {e}')

	# ── 2. Members ─────────────────────────────────────────────────────────
	members = []
	try:
		r = _requests.get(
			f'{base_url}/orgs/{org_candidate}/members',
			headers=headers, params={'per_page': 100}, timeout=15)
		if r.ok:
			members = [m['login'] for m in r.json() if isinstance(m, dict)]
			result.members_json = _json.dumps(members)
			logger.info(f'HUMINT GitHub: {len(members)} public members found')
	except Exception as e:
		logger.warning(f'HUMINT GitHub: members fetch failed: {e}')

	# ── 3. Public repos ────────────────────────────────────────────────────
	repos = []
	try:
		r = _requests.get(
			f'{base_url}/orgs/{org_candidate}/repos',
			headers=headers, params={'per_page': 100, 'sort': 'updated'}, timeout=15)
		if r.ok:
			repos = [rp['name'] for rp in r.json() if isinstance(rp, dict)]
			result.repos_json = _json.dumps(repos)
			logger.info(f'HUMINT GitHub: {len(repos)} public repos found')
	except Exception as e:
		logger.warning(f'HUMINT GitHub: repos fetch failed: {e}')

	# ── 4. Commit email harvesting (lightweight — only recent commits) ──────
	email_pattern = _re.compile(r'[\w\.\-\+]+@[\w\.\-]+\.' + _re.escape(host.split('.')[-1]))
	corp_email_pattern = _re.compile(
		r'[\w\.\-\+]+@(?:' + _re.escape(host) + '|' + _re.escape(org_candidate) + r'[\w\.\-]*)',
		_re.IGNORECASE)

	found_emails = set()
	# Only scan up to 5 most recently updated repos to stay within rate limits
	for repo_name in repos[:5]:
		try:
			r = _requests.get(
				f'{base_url}/repos/{org_candidate}/{repo_name}/commits',
				headers=headers, params={'per_page': 50}, timeout=15)
			if not r.ok:
				continue
			for commit in r.json():
				if not isinstance(commit, dict):
					continue
				author = (commit.get('commit') or {}).get('author') or {}
				email = author.get('email', '')
				if email and corp_email_pattern.search(email):
					found_emails.add(email)
					# Save to Email model & link to scan
					email_obj, _ = Email.objects.get_or_create(address=email)
					scan_history.emails.add(email_obj)
				# Also harvest from commit message
				msg = (commit.get('commit') or {}).get('message', '')
				for m in corp_email_pattern.findall(msg):
					found_emails.add(m)
		except Exception as e:
			logger.debug(f'HUMINT GitHub: commit scan error for {repo_name}: {e}')

	if found_emails:
		result.emails_found = _json.dumps(list(found_emails))
		logger.info(f'HUMINT GitHub: extracted {len(found_emails)} corp emails from commits')

	# ── 5. Naive secret-pattern detection in README files ─────────────────
	secret_patterns = [
		_re.compile(r'(?:password|passwd|secret|token|api[_\-]?key)\s*[:=]\s*["\']?([^\s"\']{8,})', _re.IGNORECASE),
		_re.compile(r'AKIA[0-9A-Z]{16}'),         # AWS access key
		_re.compile(r'ghp_[0-9A-Za-z]{36}'),       # GitHub PAT
		_re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY'),
	]
	secrets_found = []
	for repo_name in repos[:10]:
		try:
			readme_url = f'https://raw.githubusercontent.com/{org_candidate}/{repo_name}/HEAD/README.md'
			r = _requests.get(readme_url, headers=headers, timeout=10)
			if r.ok:
				for pat in secret_patterns:
					for m in pat.finditer(r.text):
						secrets_found.append({'repo': repo_name, 'match': m.group(0)[:200]})
		except Exception:
			pass

	if secrets_found:
		result.secrets_found = True
		result.secrets_json = _json.dumps(secrets_found)
		logger.warning(f'HUMINT GitHub: {len(secrets_found)} potential secrets detected!')

	result.save()

	# Enrich Employee model from member list
	for username in members[:50]:
		try:
			r = _requests.get(f'{base_url}/users/{username}', headers=headers, timeout=10)
			if r.ok:
				u = r.json()
				name = u.get('name') or username
				bio = (u.get('bio') or '')[:500]
				emp, _ = HumintEmployeeProfile.objects.get_or_create(
					scan_history=scan_history,
					full_name=name,
					defaults={
						'target_domain': domain,
						'github_url': u.get('html_url'),
						'designation': bio,
						'location': (u.get('location') or '')[:200],
						'source': 'github',
					}
				)
				# Also save to existing Employee model for UI compatibility
				Employee.objects.get_or_create(
					name=name,
					defaults={'designation': bio}
				)
		except Exception:
			pass

	logger.info(f'HUMINT GitHub Recon complete for {host}')
	return {
		'org': org_candidate,
		'members': len(members),
		'repos': len(repos),
		'emails': len(found_emails),
		'secrets': len(secrets_found),
	}


@app.task(name='humint_linkedin_recon', bind=False, queue='osint_discovery_queue')
def humint_linkedin_recon(config, host, scan_history_id, results_dir, ctx=None):
	"""Enumerate employees and profiles via LinkedIn using
	Google/Bing dorking of site:linkedin.com/in/ + company name.

	Extracts: name, title/designation, LinkedIn URL.
	Does NOT scrape LinkedIn directly — uses search engine results only.
	"""
	if ctx is None:
		ctx = {}
	import re as _re
	import requests as _requests
	from bs4 import BeautifulSoup

	logger.info(f'HUMINT LinkedIn starting for {host}')
	scan_history = ScanHistory.objects.get(pk=scan_history_id)
	domain = scan_history.domain

	from tldextract import extract as _tld_extract
	tld = _tld_extract(host)
	company = tld.domain.replace('-', ' ').replace('_', ' ')

	# Use proxy to avoid Bing blocking Docker server IP
	proxy_url = get_random_proxy(proxy_mode=ctx.get('proxy_mode', 'auto'))
	proxies = {'http': proxy_url, 'https': proxy_url} if proxy_url else None

	# Rotate User-Agents to reduce fingerprinting
	_user_agents = [
		'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
		'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
		'Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0',
	]

	found_profiles = []
	# Use multiple search engines — Bing + DuckDuckGo HTML
	queries = [
		f'site:linkedin.com/in/ "{company}"',
		f'site:linkedin.com/in/ "{host}" employee',
	]
	search_engines = [
		('bing', 'https://www.bing.com/search?q={query}&count=50'),
		('ddg', 'https://html.duckduckgo.com/html/?q={query}'),
	]

	for query in queries:
		for engine_name, url_template in search_engines:
			try:
				headers = {
					'User-Agent': random.choice(_user_agents),
					'Accept-Language': 'en-US,en;q=0.9',
				}
				url = url_template.format(query=_requests.utils.quote(query))
				r = _requests.get(url, headers=headers, proxies=proxies, timeout=25, verify=False)
				if not r.ok:
					logger.debug(f'HUMINT LinkedIn: {engine_name} returned {r.status_code}')
					continue
				soup = BeautifulSoup(r.text, 'lxml')
				# Bing: li.b_algo > a, DDG: a.result__a
				link_tags = soup.find_all('a', href=True)
				for link_tag in link_tags:
					link = link_tag.get('href', '')
					if 'linkedin.com/in/' not in link:
						continue
					title_text = link_tag.get_text(strip=True)
					# Heuristic: "Name - Title at Company | LinkedIn"
					parts = title_text.split(' - ')
					name = parts[0].strip() if parts else title_text
					designation = parts[1].split('|')[0].strip() if len(parts) > 1 else ''
					if name and name not in [p['name'] for p in found_profiles]:
						found_profiles.append({
							'name': name[:500],
							'designation': designation[:500],
							'linkedin_url': link[:500],
							'source': f'linkedin_{engine_name}_dork',
						})
				if found_profiles:
					break  # got results from this engine, skip remaining engines for this query
			except Exception as e:
				logger.debug(f'HUMINT LinkedIn: {engine_name} search error: {e}')
		# Small delay between queries
		if queries.index(query) < len(queries) - 1:
			time.sleep(random.randint(3, 6))

	logger.info(f'HUMINT LinkedIn: found {len(found_profiles)} profiles for {host}')

	for profile in found_profiles[:100]:
		try:
			# Save enriched profile
			HumintEmployeeProfile.objects.get_or_create(
				scan_history=scan_history,
				full_name=profile['name'],
				defaults={
					'target_domain': domain,
					'designation': profile['designation'],
					'linkedin_url': profile['linkedin_url'],
					'source': 'linkedin',
				}
			)
			# Keep existing Employee model updated for UI
			Employee.objects.get_or_create(
				name=profile['name'],
				defaults={'designation': profile['designation']}
			)
		except Exception as e:
			logger.debug(f'HUMINT LinkedIn: save error: {e}')

	return {'profiles_found': len(found_profiles)}


@app.task(name='humint_job_postings', bind=False, queue='osint_discovery_queue')
def humint_job_postings(config, host, scan_history_id, results_dir, ctx=None):
	"""Scrape public job postings to extract technology stack intelligence.

	Job postings reveal internal tools, languages, frameworks, and
	infrastructure — critical for attack surface mapping.
	Sources: Indeed, LinkedIn Jobs, Glassdoor (via Google dorking).
	"""
	if ctx is None:
		ctx = {}
	import re as _re
	import requests as _requests
	from bs4 import BeautifulSoup

	logger.info(f'HUMINT Job Postings starting for {host}')
	scan_history = ScanHistory.objects.get(pk=scan_history_id)
	domain = scan_history.domain

	from tldextract import extract as _tld_extract
	tld = _tld_extract(host)
	company = tld.domain

	# Technology keywords to extract from job descriptions
	TECH_PATTERNS = [
		# Languages
		r'\b(Python|Java|JavaScript|TypeScript|Go|Golang|Rust|PHP|Ruby|C#|C\+\+|Scala|Kotlin|Swift)\b',
		# Frameworks
		r'\b(Django|Laravel|Spring|Rails|Express|React|Vue|Angular|Next\.js|FastAPI|Flask)\b',
		# Databases
		r'\b(PostgreSQL|MySQL|MongoDB|Redis|Elasticsearch|Cassandra|Oracle|MSSQL|MariaDB|DynamoDB)\b',
		# Cloud/Infra
		r'\b(AWS|Azure|GCP|Kubernetes|Docker|Terraform|Ansible|Jenkins|GitLab CI|GitHub Actions|Helm)\b',
		# Security-relevant
		r'\b(LDAP|Active Directory|SAML|OAuth|Okta|VPN|WAF|Palo Alto|Fortinet|Cisco|Splunk|SIEM)\b',
		# Web servers
		r'\b(Nginx|Apache|IIS|Tomcat|Jetty|HAProxy|Traefik|Caddy)\b',
	]

	# Use proxy to avoid Bing/DDG blocking Docker server IP
	proxy_url = get_random_proxy(proxy_mode=ctx.get('proxy_mode', 'auto'))
	proxies = {'http': proxy_url, 'https': proxy_url} if proxy_url else None

	_user_agents = [
		'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
		'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
		'Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0',
	]

	sources = [
		('indeed', f'site:indeed.com "{company}" jobs'),
		('linkedin', f'site:linkedin.com/jobs/view "{company}"'),
		('glassdoor', f'site:glassdoor.com/job-listing "{company}"'),
		('jobsdb', f'site:jobsdb.com "{company}"'),
	]

	# Each source query is tried on Bing first, then DDG as fallback
	_search_engines = [
		('bing', 'https://www.bing.com/search?q={query}&count=20'),
		('ddg', 'https://html.duckduckgo.com/html/?q={query}'),
	]

	all_techs = set()
	total_jobs = 0

	for source_name, query in sources:
		source_found = False
		for eng_name, eng_template in _search_engines:
			if source_found:
				break
			try:
				headers = {
					'User-Agent': random.choice(_user_agents),
					'Accept-Language': 'en-US,en;q=0.9',
				}
				url = eng_template.format(query=_requests.utils.quote(query))
				r = _requests.get(url, headers=headers, proxies=proxies, timeout=25, verify=False)
				if not r.ok:
					logger.debug(f'HUMINT Jobs: {eng_name} returned {r.status_code} for {source_name}')
					continue
				soup = BeautifulSoup(r.text, 'lxml')
				# Generic: find all links, filter by content
				for link_tag in soup.find_all('a', href=True):
					job_url = link_tag.get('href', '')
					title_text = link_tag.get_text(strip=True)
					if not title_text or len(title_text) < 5:
						continue
					# Find surrounding snippet text
					parent = link_tag.find_parent(['li', 'div'])
					snippet = ''
					if parent:
						snippet_el = parent.find('p') or parent.find('span', class_=True)
						snippet = snippet_el.get_text(strip=True) if snippet_el else ''
					combined_text = f'{title_text} {snippet}'
					# Extract technologies
					job_techs = []
					for pat in TECH_PATTERNS:
						for m in _re.finditer(pat, combined_text, _re.IGNORECASE):
							t = m.group(0).strip()
							job_techs.append(t)
							all_techs.add(t)
					if title_text and job_techs:
						try:
							HumintJobPosting.objects.get_or_create(
								scan_history=scan_history,
								url=job_url[:1000] or 'unknown',
								defaults={
									'target_domain': domain,
									'title': title_text[:500],
									'company': company[:300],
									'source': source_name,
									'technologies': list(set(job_techs))[:20],
									'raw_description': snippet[:2000],
								}
							)
							total_jobs += 1
							source_found = True
						except Exception as e:
							logger.debug(f'HUMINT Jobs: save error: {e}')
			except Exception as e:
				logger.debug(f'HUMINT Jobs: {eng_name}/{source_name} error: {e}')
		# Delay between sources
		time.sleep(random.randint(3, 6))

	logger.info(
		f'HUMINT Job Postings: {total_jobs} postings, '
		f'{len(all_techs)} technologies found for {host}: {", ".join(sorted(all_techs)[:20])}'
	)
	return {'jobs_found': total_jobs, 'technologies': list(all_techs)}


###############################################################################
# SIGINT — Signals Intelligence Tasks
###############################################################################

@app.task(name='sigint_asn_recon', bind=False, queue='osint_discovery_queue')
def sigint_asn_recon(config, host, scan_history_id, results_dir, ctx=None):
	"""Enumerate ASN, BGP prefixes, and CIDR ranges owned by the target
	organization using:
	  1. BGPView public REST API (no API key needed)
	  2. amass intel -whois -d <domain>  (finds org-linked ASNs)
	  3. ARIN/RIPE/APNIC RDAP lookup for IP ranges
	"""
	if ctx is None:
		ctx = {}
	import json as _json
	import requests as _requests

	logger.info(f'SIGINT ASN Recon starting for {host}')
	scan_history = ScanHistory.objects.get(pk=scan_history_id)
	domain = scan_history.domain
	history_file = f'{results_dir}/commands.txt'

	from tldextract import extract as _tld_extract
	tld = _tld_extract(host)
	org_name = tld.domain

	headers = {'User-Agent': 'paraKang-SIGINT/2.0'}
	found_asns = []

	# ── 1. BGPView: search by ORG name ─────────────────────────────────────
	try:
		r = _requests.get(
			f'https://api.bgpview.io/search?query_term={_requests.utils.quote(org_name)}',
			headers=headers, timeout=20)
		if r.ok:
			data = r.json().get('data', {})
			for asn_info in (data.get('asns') or [])[:10]:
				asn_num = asn_info.get('asn')
				if not asn_num:
					continue
				found_asns.append({
					'asn': f'AS{asn_num}',
					'name': asn_info.get('name', ''),
					'description': asn_info.get('description_short', ''),
					'country': asn_info.get('country_code', ''),
				})
				logger.info(f'SIGINT ASN: found AS{asn_num} — {asn_info.get("name")}')
	except Exception as e:
		logger.warning(f'SIGINT ASN: BGPView search failed: {e}')

	# ── 2. For each ASN, fetch its prefixes via BGPView ───────────────────
	for asn_entry in found_asns:
		asn_num = asn_entry['asn'].lstrip('AS')
		try:
			r = _requests.get(
				f'https://api.bgpview.io/asn/{asn_num}/prefixes',
				headers=headers, timeout=20)
			if not r.ok:
				continue
			data = r.json().get('data', {})
			v4 = [p['prefix'] for p in (data.get('ipv4_prefixes') or [])[:50]]
			asn_entry['cidrs'] = v4
			asn_entry['ip_count'] = sum(
				2 ** (32 - int(p.split('/')[1])) for p in v4 if '/' in p)
		except Exception as e:
			logger.debug(f'SIGINT ASN: prefix fetch failed for {asn_entry["asn"]}: {e}')

	# ── 3. Also run amass intel -whois ─────────────────────────────────────
	amass_output = f'{results_dir}/sigint_amass_intel.txt'
	try:
		import shlex as _shlex
		safe_host = _shlex.quote(host)
		run_command(
			f'amass intel -whois -d {safe_host} -o {amass_output} -silent',
			shell=True,
			history_file=history_file,
			scan_id=scan_history_id,
		)
		if os.path.isfile(amass_output):
			with open(amass_output) as f:
				amass_lines = [l.strip() for l in f if l.strip()]
			logger.info(f'SIGINT ASN: amass intel found {len(amass_lines)} related domains/IPs')
	except Exception as e:
		logger.warning(f'SIGINT ASN: amass intel failed: {e}')

	# ── 4. Save records ────────────────────────────────────────────────────
	saved = 0
	for entry in found_asns:
		try:
			SigintAsnRecord.objects.get_or_create(
				scan_history=scan_history,
				asn=entry['asn'],
				defaults={
					'target_domain': domain,
					'org_name': entry.get('name', '')[:300],
					'country': entry.get('country', '')[:100],
					'registry': 'bgpview',
					'cidr_ranges': entry.get('cidrs', [])[:50],
					'ip_count': entry.get('ip_count', 0),
				}
			)
			saved += 1
		except Exception as e:
			logger.debug(f'SIGINT ASN: save error: {e}')

	logger.info(f'SIGINT ASN Recon complete — {saved} ASN records saved for {host}')
	return {'asns_found': saved, 'records': [e['asn'] for e in found_asns]}


@app.task(name='sigint_email_security', bind=False, queue='osint_discovery_queue')
def sigint_email_security(config, host, scan_history_id, results_dir, ctx=None):
	"""Analyze email security posture of the target domain:
	  - SPF record validation and policy strength
	  - DMARC record analysis and enforcement level
	  - DKIM selector probing (common selectors)
	  - MX record discovery and mail provider fingerprinting
	  - Spoofing risk assessment

	High-value output: weak DMARC/SPF = target is spoofable for phishing.
	"""
	if ctx is None:
		ctx = {}
	import json as _json
	import dns.resolver as _dns

	logger.info(f'SIGINT Email Security starting for {host}')
	scan_history = ScanHistory.objects.get(pk=scan_history_id)
	domain_obj = scan_history.domain

	# Also check root domain if host is a subdomain
	from tldextract import extract as _tld_extract
	tld = _tld_extract(host)
	root_domain = f'{tld.domain}.{tld.suffix}'

	domains_to_check = list(dict.fromkeys([host, root_domain]))  # dedup, preserve order

	DKIM_SELECTORS = [
		'default', 'selector1', 'selector2', 'google', 'mail', 'email',
		'dkim', 'k1', 'k2', 's1', 's2', 'smtp', 'mandrill', 'sendgrid',
		'mailchimp', 'amazonses', 'pm', 'key1', 'key2', 'zoho',
	]

	MAIL_PROVIDER_FINGERPRINTS = {
		'google': 'Google Workspace',
		'googlemail': 'Google Workspace',
		'outlook': 'Microsoft 365',
		'hotmail': 'Microsoft 365',
		'protection.outlook': 'Microsoft 365',
		'mimecast': 'Mimecast',
		'pphosted': 'Proofpoint',
		'barracuda': 'Barracuda',
		'sendgrid': 'SendGrid',
		'mailchimp': 'Mailchimp/Mandrill',
		'amazonses': 'Amazon SES',
		'zoho': 'Zoho Mail',
		'yandex': 'Yandex Mail',
	}

	for domain_str in domains_to_check:
		record = SigintEmailSecurity(
			scan_history=scan_history,
			target_domain=domain_obj,
			domain_checked=domain_str,
		)

		# ── SPF ─────────────────────────────────────────────────────────
		try:
			answers = _dns.resolve(domain_str, 'TXT', lifetime=8)
			for rdata in answers:
				txt = str(rdata).strip('"')
				if txt.startswith('v=spf1'):
					record.spf_record = txt[:2000]
					record.spf_valid = True
					if '-all' in txt:
						record.spf_policy = 'fail'
					elif '~all' in txt:
						record.spf_policy = 'softfail'
					elif '?all' in txt:
						record.spf_policy = 'neutral'
					elif '+all' in txt:
						record.spf_policy = 'pass_all'  # dangerous!
					else:
						record.spf_policy = 'none'
					break
		except Exception:
			record.spf_valid = False
			record.spf_policy = 'none'

		# ── DMARC ───────────────────────────────────────────────────────
		try:
			dmarc_domain = f'_dmarc.{domain_str}'
			answers = _dns.resolve(dmarc_domain, 'TXT', lifetime=8)
			for rdata in answers:
				txt = str(rdata).strip('"')
				if 'v=DMARC1' in txt:
					record.dmarc_record = txt[:2000]
					record.dmarc_valid = True
					if 'p=reject' in txt:
						record.dmarc_policy = 'reject'
					elif 'p=quarantine' in txt:
						record.dmarc_policy = 'quarantine'
					else:
						record.dmarc_policy = 'none'
					import re as _re
					pct_m = _re.search(r'pct=(\d+)', txt)
					record.dmarc_pct = int(pct_m.group(1)) if pct_m else 100
					break
		except Exception:
			record.dmarc_valid = False
			record.dmarc_policy = 'none'

		# ── DKIM selectors probe ────────────────────────────────────────
		found_selectors = []
		dkim_records = {}
		for sel in DKIM_SELECTORS:
			try:
				dkim_domain = f'{sel}._domainkey.{domain_str}'
				answers = _dns.resolve(dkim_domain, 'TXT', lifetime=5)
				for rdata in answers:
					txt = str(rdata).strip('"')
					if 'p=' in txt or 'v=DKIM1' in txt:
						found_selectors.append(sel)
						dkim_records[sel] = txt[:500]
						break
			except Exception:
				pass
		record.dkim_selectors = found_selectors
		record.dkim_records = _json.dumps(dkim_records)

		# ── MX records & mail provider ──────────────────────────────────
		mx_list = []
		try:
			answers = _dns.resolve(domain_str, 'MX', lifetime=8)
			for rdata in answers:
				mx_host = str(rdata.exchange).rstrip('.').lower()
				mx_list.append({'priority': rdata.preference, 'host': mx_host})
			record.mx_records = _json.dumps(mx_list)
			# Fingerprint mail provider
			all_mx = ' '.join(m['host'] for m in mx_list)
			for pattern, provider in MAIL_PROVIDER_FINGERPRINTS.items():
				if pattern in all_mx:
					record.mail_provider = provider
					break
		except Exception:
			pass

		# ── Spoofing risk assessment ────────────────────────────────────
		reasons = []
		risk = 'low'
		if not record.spf_valid:
			reasons.append('No SPF record')
			risk = 'high'
		elif record.spf_policy in ('none', 'pass_all', 'neutral'):
			reasons.append(f'Weak SPF policy: {record.spf_policy}')
			risk = 'high' if record.spf_policy == 'pass_all' else 'medium'
		if not record.dmarc_valid:
			reasons.append('No DMARC record')
			risk = 'high'
		elif record.dmarc_policy == 'none':
			reasons.append('DMARC policy=none (monitoring only, not enforcing)')
			if risk != 'high':
				risk = 'medium'
		elif record.dmarc_policy == 'quarantine' and (record.dmarc_pct or 100) < 100:
			reasons.append(f'DMARC quarantine only {record.dmarc_pct}% of messages')
			if risk != 'high':
				risk = 'medium'
		if not found_selectors:
			reasons.append('No DKIM selectors found')

		record.spoofing_risk = risk
		record.risk_reasons = '; '.join(reasons) if reasons else 'Email security posture is strong'

		logger.info(
			f'SIGINT Email Security: {domain_str} — '
			f'SPF:{record.spf_policy} DMARC:{record.dmarc_policy} '
			f'Risk:{risk}'
		)

		try:
			record.save()
		except Exception as e:
			logger.warning(f'SIGINT Email Security: save error for {domain_str}: {e}')

	return {
		'domains_checked': domains_to_check,
		'high_risk': [d for d in domains_to_check if
			SigintEmailSecurity.objects.filter(
				scan_history=scan_history, domain_checked=d, spoofing_risk='high').exists()]
	}


@app.task(name='sigint_passive_intel', bind=False, queue='osint_discovery_queue')
def sigint_passive_intel(config, host, scan_history_id, results_dir, ctx=None):
	"""Collect passive threat intelligence from Shodan and Censys
	for all IP addresses already discovered for this scan.

	Requires API keys to be configured via the web UI:
	  Settings → API Vault → Shodan / Censys
	Falls back gracefully when keys are not configured.
	"""
	if ctx is None:
		ctx = {}
	import json as _json

	logger.info(f'SIGINT Passive Intel starting for {host}')
	scan_history = ScanHistory.objects.get(pk=scan_history_id)
	domain_obj = scan_history.domain

	# Read API keys from the database (configured via Settings → API Vault in the UI)
	_shodan_obj = ShodanAPIKey.objects.first()
	shodan_key = _shodan_obj.key if _shodan_obj and _shodan_obj.key else None
	_censys_obj = CensysAPIKey.objects.first()
	censys_id = _censys_obj.api_id if _censys_obj and _censys_obj.api_id else None
	censys_secret = _censys_obj.secret if _censys_obj and _censys_obj.secret else None

	# Collect unique IPs from this scan
	ip_qs = IpAddress.objects.filter(
		subdomain__scan_history=scan_history
	).values_list('address', flat=True).distinct()
	ips = [ip for ip in ip_qs if ip and not ip.startswith(('10.', '172.', '192.168.', '127.'))]

	if not ips:
		logger.info(f'SIGINT Passive Intel: no external IPs found for scan, skipping')
		return {'ips_queried': 0}

	saved = 0

	# ── Shodan ──────────────────────────────────────────────────────────────
	if shodan_key:
		try:
			import shodan as _shodan
			api = _shodan.Shodan(shodan_key)
			for ip in ips[:20]:  # respect rate limits
				try:
					host_info = api.host(ip)
					open_ports = host_info.get('ports', [])
					services = {}
					vulns = list(host_info.get('vulns', {}).keys())
					for item in host_info.get('data', []):
						port = item.get('port')
						if port:
							services[str(port)] = {
								'transport': item.get('transport', 'tcp'),
								'product': item.get('product', ''),
								'version': item.get('version', ''),
								'banner': (item.get('data') or '')[:200],
							}
					SigintIntelligenceRecord.objects.get_or_create(
						scan_history=scan_history,
						ip_address=ip,
						source='shodan',
						defaults={
							'target_domain': domain_obj,
							'hostname': (host_info.get('hostnames') or [''])[0][:500],
							'org': (host_info.get('org') or '')[:300],
							'isp': (host_info.get('isp') or '')[:300],
							'country': (host_info.get('country_name') or '')[:100],
							'city': (host_info.get('city') or '')[:100],
							'asn': (host_info.get('asn') or '')[:30],
							'os': (host_info.get('os') or '')[:200],
							'last_update': (host_info.get('last_update') or '')[:50],
							'open_ports': open_ports[:50],
							'services_json': _json.dumps(services),
							'vulns_json': _json.dumps(vulns),
							'tags': list(host_info.get('tags') or [])[:20],
							'is_cloud': any(k in (host_info.get('org') or '').lower()
								for k in ['amazon', 'google', 'microsoft', 'alibaba', 'cloudflare']),
						}
					)
					saved += 1
				except Exception as se:
					logger.debug(f'SIGINT Shodan: query failed for {ip}: {se}')
			logger.info(f'SIGINT Shodan: queried {len(ips)} IPs, saved {saved} records')
		except Exception as e:
			logger.warning(f'SIGINT Shodan: initialization failed: {e}')

	# ── Censys ──────────────────────────────────────────────────────────────
	if censys_id and censys_secret and not shodan_key:
		try:
			from censys.search import CensysHosts
			h = CensysHosts(api_id=censys_id, api_secret=censys_secret)
			for ip in ips[:10]:
				try:
					result = h.view(ip)
					services = {}
					open_ports = []
					for svc in result.get('services', []):
						port = svc.get('port')
						if port:
							open_ports.append(port)
							services[str(port)] = {
								'transport': svc.get('transport_protocol', 'TCP'),
								'service': svc.get('service_name', ''),
								'banner': (svc.get('banner') or '')[:200],
							}
					SigintIntelligenceRecord.objects.get_or_create(
						scan_history=scan_history,
						ip_address=ip,
						source='censys',
						defaults={
							'target_domain': domain_obj,
							'org': (result.get('autonomous_system', {}).get('name') or '')[:300],
							'country': (result.get('location', {}).get('country') or '')[:100],
							'city': (result.get('location', {}).get('city') or '')[:100],
							'asn': str(result.get('autonomous_system', {}).get('asn') or '')[:30],
							'open_ports': open_ports[:50],
							'services_json': _json.dumps(services),
							'tags': list(result.get('labels') or [])[:20],
						}
					)
					saved += 1
				except Exception as ce:
					logger.debug(f'SIGINT Censys: query failed for {ip}: {ce}')
		except Exception as e:
			logger.warning(f'SIGINT Censys: initialization failed: {e}')

	# ── Fallback: Shodan InternetDB (no API key, rate-limited) ───────────
	if not shodan_key and not (censys_id and censys_secret):
		import requests as _requests
		logger.info('SIGINT Passive Intel: no API keys — using Shodan InternetDB (limited)')
		for ip in ips[:10]:
			try:
				r = _requests.get(
					f'https://internetdb.shodan.io/{ip}',
					timeout=10,
					headers={'User-Agent': 'paraKang-SIGINT/2.0'})
				if r.ok:
					d = r.json()
					SigintIntelligenceRecord.objects.get_or_create(
						scan_history=scan_history,
						ip_address=ip,
						source='shodan_idb',
						defaults={
							'target_domain': domain_obj,
							'hostname': (d.get('hostnames') or [''])[0][:500] if d.get('hostnames') else '',
							'open_ports': (d.get('ports') or [])[:50],
							'tags': (d.get('tags') or [])[:20],
							'vulns_json': _json.dumps(d.get('vulns') or []),
						}
					)
					saved += 1
			except Exception as e:
				logger.debug(f'SIGINT InternetDB: {ip} failed: {e}')

	logger.info(f'SIGINT Passive Intel complete — {saved} records for {host}')
	return {'ips_queried': len(ips), 'records_saved': saved}


@app.task(name='sigint_cert_analysis', bind=False, queue='osint_discovery_queue')
def sigint_cert_analysis(config, host, scan_history_id, results_dir, ctx=None):
	"""Deep SSL/TLS certificate analysis for all discovered subdomains.

	For each subdomain with a known HTTP endpoint, perform:
	  1. Live TLS handshake — extract full cert chain info
	  2. CT log enrichment via crt.sh API — find extra SANs / older certs
	  3. Anomaly detection:
	     - Expired or near-expiry certificates (< 30 days)
	     - Self-signed certificates
	     - Weak algorithms (SHA1, MD5, 512-bit keys)
	     - Wildcard certificates
	     - Mismatched SAN domains (scope expansion)
	"""
	if ctx is None:
		ctx = {}
	import json as _json
	import ssl as _ssl
	import socket as _socket
	import datetime as _dt
	import requests as _requests
	from cryptography import x509 as _x509
	from cryptography.hazmat.backends import default_backend as _default_backend
	from cryptography.hazmat.primitives import hashes as _hashes

	logger.info(f'SIGINT Cert Analysis starting for {host}')
	scan_history = ScanHistory.objects.get(pk=scan_history_id)
	domain_obj = scan_history.domain

	# Gather subdomains for this scan
	subdomains = Subdomain.objects.filter(
		scan_history=scan_history).values_list('name', flat=True)

	saved = 0
	all_san_domains = set()

	def analyze_cert(hostname, port=443):
		"""Fetch and analyze a TLS certificate, return parsed dict."""
		ctx_ssl = _ssl.create_default_context()
		ctx_ssl.check_hostname = False
		ctx_ssl.verify_mode = _ssl.CERT_NONE
		try:
			with _socket.create_connection((hostname, port), timeout=8) as sock:
				with ctx_ssl.wrap_socket(sock, server_hostname=hostname) as ssock:
					der = ssock.getpeercert(binary_form=True)
		except Exception as e:
			return None, str(e)

		try:
			cert = _x509.load_der_x509_certificate(der, _default_backend())
		except Exception as e:
			return None, str(e)

		now = _dt.datetime.now(_dt.timezone.utc)
		# Support both cryptography < 42 (not_valid_after) and >= 42 (not_valid_after_utc)
		try:
			not_after = cert.not_valid_after_utc
			not_before = cert.not_valid_before_utc
		except AttributeError:
			not_after = cert.not_valid_after.replace(tzinfo=_dt.timezone.utc)
			not_before = cert.not_valid_before.replace(tzinfo=_dt.timezone.utc)
		days_to_expiry = (not_after - now).days

		# Subject fields
		cn = None
		for attr in cert.subject:
			if attr.oid == _x509.NameOID.COMMON_NAME:
				cn = attr.value
				break

		# Issuer
		issuer_cn = None
		issuer_org = None
		for attr in cert.issuer:
			if attr.oid == _x509.NameOID.COMMON_NAME:
				issuer_cn = attr.value
			if attr.oid == _x509.NameOID.ORGANIZATION_NAME:
				issuer_org = attr.value

		# SAN
		san_list = []
		try:
			san_ext = cert.extensions.get_extension_for_oid(
				_x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
			san_list = [n.value for n in san_ext.value if isinstance(n, _x509.DNSName)]
		except Exception:
			pass

		# Key info
		pub_key = cert.public_key()
		key_algo = type(pub_key).__name__.replace('_RSAPublicKey', 'RSA').replace('_EllipticCurvePublicKey', 'EC').replace('_DSAPublicKey', 'DSA')
		key_bits = None
		try:
			key_bits = pub_key.key_size
		except AttributeError:
			pass

		# Fingerprint
		fp = cert.fingerprint(_hashes.SHA256()).hex()

		# Anomaly checks
		is_self_signed = (cert.subject == cert.issuer)
		is_wildcard = any('*.' in s for s in san_list + ([cn] if cn else []))
		sig_algo = cert.signature_algorithm_oid.dotted_string
		uses_deprecated = 'sha1' in (cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else '').lower()

		return {
			'common_name': (cn or '')[:500],
			'issuer': (issuer_cn or '')[:500],
			'issuer_org': (issuer_org or '')[:300],
			'san_domains': san_list[:50],
			'not_before': not_before,
			'not_after': not_after,
			'is_expired': days_to_expiry < 0,
			'days_to_expiry': days_to_expiry,
			'cert_fingerprint': fp[:200],
			'serial_number': str(cert.serial_number)[:200],
			'key_algorithm': key_algo[:50],
			'key_bits': key_bits,
			'is_self_signed': is_self_signed,
			'is_wildcard': is_wildcard,
			'uses_deprecated_algo': uses_deprecated,
		}, None

	# Analyze each subdomain
	for subdomain_name in list(subdomains)[:50]:
		parsed, err = analyze_cert(subdomain_name)
		if not parsed:
			logger.debug(f'SIGINT Cert: {subdomain_name} TLS failed: {err}')
			continue
		try:
			rec, created = SigintCertificateRecord.objects.get_or_create(
				scan_history=scan_history,
				source_host=subdomain_name,
				cert_fingerprint=parsed['cert_fingerprint'],
				defaults={
					'target_domain': domain_obj,
					'source_port': 443,
					**{k: v for k, v in parsed.items() if k not in ('cert_fingerprint',)},
				}
			)
			if created:
				saved += 1
				all_san_domains.update(parsed['san_domains'])
				if parsed['is_expired']:
					logger.warning(f'SIGINT Cert: EXPIRED cert on {subdomain_name}!')
				elif parsed['days_to_expiry'] < 30:
					logger.warning(f'SIGINT Cert: cert on {subdomain_name} expires in {parsed["days_to_expiry"]} days!')
				if parsed['is_self_signed']:
					logger.warning(f'SIGINT Cert: SELF-SIGNED cert on {subdomain_name}')
		except Exception as e:
			logger.debug(f'SIGINT Cert: save error for {subdomain_name}: {e}')

	# CT log enrichment via crt.sh — finds certs from history
	try:
		r = _requests.get(
			f'https://crt.sh/?q=%.{host}&output=json',
			timeout=20,
			headers={'User-Agent': 'paraKang-SIGINT/2.0'})
		if r.ok:
			ct_entries = r.json()
			for entry in ct_entries[:200]:
				name_value = entry.get('name_value', '')
				for name in name_value.split('\n'):
					name = name.strip().lstrip('*.')
					if name and name not in all_san_domains and name.endswith(host):
						all_san_domains.add(name)
			logger.info(f'SIGINT Cert: CT log found {len(ct_entries)} cert entries for {host}')
	except Exception as e:
		logger.warning(f'SIGINT Cert: crt.sh query failed: {e}')

	# Save any newly discovered SAN domains as subdomains
	new_sub_count = 0
	for san in all_san_domains:
		if san.endswith(host) and san != host:
			try:
				subdomain_obj, created = Subdomain.objects.get_or_create(
					name=san,
					scan_history=scan_history,
					defaults={'target_domain': domain_obj}
				)
				if created:
					new_sub_count += 1
			except Exception:
				pass

	logger.info(
		f'SIGINT Cert Analysis complete: {saved} certs analyzed, '
		f'{new_sub_count} new subdomains from SANs for {host}'
	)
	return {
		'certs_analyzed': saved,
		'new_subdomains_from_san': new_sub_count,
		'unique_sans': len(all_san_domains),
	}


@app.task(name='dorking', bind=False, queue='dorking_queue')
def dorking(config, host, scan_history_id, results_dir):
	"""Run Google dorks.

	Args:
		config (dict): yaml_configuration
		host (str): target name
		scan_history_id (startScan.ScanHistory): Scan History ID
		results_dir (str): Path to store scan results

	Returns:
		list: Dorking results for each dork ran.
	"""
	# Some dork sources: https://github.com/six2dez/degoogle_hunter/blob/master/degoogle_hunter.sh
	scan_history = ScanHistory.objects.get(pk=scan_history_id)
	dorks = config.get(OSINT_DORK, [])
	custom_dorks = config.get(OSINT_CUSTOM_DORK, [])
	results = []
	google_blocked = False  # Track if Google has blocked this IP session

	# Auto-fetch free proxies if no proxy is configured, to reduce Google IP-block risk
	try:
		proxy_obj = Proxy.objects.first()
		if not proxy_obj or not proxy_obj.use_proxy or not proxy_obj.proxies.strip():
			logger.info('Dorking: no proxy configured — auto-fetching free proxies ...')
			fetch_result = fetch_free_proxies()
			if fetch_result.get('total', 0) > 0:
				proxy_obj = Proxy.objects.first()
				if proxy_obj and proxy_obj.proxies.strip():
					proxy_obj.use_proxy = True
					proxy_obj.save()
					logger.info(f'Dorking: {fetch_result["total"]} proxy/proxies now active for GooFuzz')
			else:
				logger.warning('Dorking: auto-fetch returned no proxies — proceeding without proxy')
	except Exception as _proxy_e:
		logger.warning(f'Dorking: proxy auto-fetch failed: {_proxy_e}')

	# custom dorking has higher priority
	try:
		for custom_dork in custom_dorks:
			lookup_target = custom_dork.get('lookup_site')
			# replace with original host if _target_
			lookup_target = host if lookup_target == '_target_' else lookup_target
			if 'lookup_extensions' in custom_dork:
				res = get_and_save_dork_results(
					lookup_target=lookup_target,
					results_dir=results_dir,
					type='custom_dork',
					lookup_extensions=custom_dork.get('lookup_extensions'),
					scan_history=scan_history
				)
				if res is _GOOFUZZ_BLOCKED:
					google_blocked = True; break
				results += res or []
			elif 'lookup_keywords' in custom_dork:
				res = get_and_save_dork_results(
					lookup_target=lookup_target,
					results_dir=results_dir,
					type='custom_dork',
					lookup_keywords=custom_dork.get('lookup_keywords'),
					scan_history=scan_history
				)
				if res is _GOOFUZZ_BLOCKED:
					google_blocked = True; break
				results += res or []
	except Exception as e:
		logger.exception(e)

	# default dorking
	try:
		for _dork_idx, dork in enumerate(dorks):
			if google_blocked:
				logger.warning(f'Dorking: Google blocked — skipping remaining {len(dorks) - _dork_idx} dork types.')
				break
			if _dork_idx > 0:
				_wait = random.randint(8, 15)
				logger.info(f'Dorking: sleeping {_wait}s between dork types to avoid Google rate-limit')
				time.sleep(_wait)
			logger.info(f'Getting dork information for {dork}')
			if dork == 'stackoverflow':
				res = get_and_save_dork_results(
					lookup_target='stackoverflow.com',
					results_dir=results_dir,
					type=dork,
					lookup_keywords=host,
					scan_history=scan_history
				)
				if res is _GOOFUZZ_BLOCKED: google_blocked = True; continue
				results += res or []

			elif dork == 'login_pages':
				res = get_and_save_dork_results(
					lookup_target=host,
					results_dir=results_dir,
					type=dork,
					lookup_keywords='/login/,login.html',
					page_count=5,
					scan_history=scan_history
				)
				if res is _GOOFUZZ_BLOCKED: google_blocked = True; continue
				results += res or []

			elif dork == 'admin_panels':
				res = get_and_save_dork_results(
					lookup_target=host,
					results_dir=results_dir,
					type=dork,
					lookup_keywords='/admin/,admin.html',
					page_count=5,
					scan_history=scan_history
				)
				if res is _GOOFUZZ_BLOCKED: google_blocked = True; continue
				results += res or []

			elif dork == 'dashboard_pages':
				res = get_and_save_dork_results(
					lookup_target=host,
					results_dir=results_dir,
					type=dork,
					lookup_keywords='/dashboard/,dashboard.html',
					page_count=5,
					scan_history=scan_history
				)
				if res is _GOOFUZZ_BLOCKED: google_blocked = True; continue
				results += res or []

			elif dork == 'social_media' :
				social_websites = [
					'tiktok.com',
					'facebook.com',
					'twitter.com',
					'youtube.com',
					'reddit.com'
				]
				for _si, site in enumerate(social_websites):
					if google_blocked:
						break
					if _si > 0:
						time.sleep(random.randint(5, 10))
					res = get_and_save_dork_results(
						lookup_target=site,
						results_dir=results_dir,
						type=dork,
						lookup_keywords=host,
						scan_history=scan_history
					)
					if res is _GOOFUZZ_BLOCKED:
						google_blocked = True; break
					results += res or []

			elif dork == 'project_management' :
				project_websites = [
					'trello.com',
					'atlassian.net'
				]
				for _pi, site in enumerate(project_websites):
					if google_blocked:
						break
					if _pi > 0:
						time.sleep(random.randint(5, 10))
					res = get_and_save_dork_results(
						lookup_target=site,
						results_dir=results_dir,
						type=dork,
						lookup_keywords=host,
						scan_history=scan_history
					)
					if res is _GOOFUZZ_BLOCKED:
						google_blocked = True; break
					results += res or []

			elif dork == 'code_sharing' :
				project_websites = [
					'github.com',
					'gitlab.com',
					'bitbucket.org'
				]
				for _ci, site in enumerate(project_websites):
					if google_blocked:
						break
					if _ci > 0:
						time.sleep(random.randint(5, 10))
					res = get_and_save_dork_results(
						lookup_target=site,
						results_dir=results_dir,
						type=dork,
						lookup_keywords=host,
						scan_history=scan_history
					)
					if res is _GOOFUZZ_BLOCKED:
						google_blocked = True; break
					results += res or []

			elif dork == 'config_files' :
				config_file_exts = [
					'env',
					'xml',
					'conf',
					'toml',
					'yml',
					'yaml',
					'cnf',
					'inf',
					'rdp',
					'ora',
					'txt',
					'cfg',
					'ini'
				]
				res = get_and_save_dork_results(
					lookup_target=host,
					results_dir=results_dir,
					type=dork,
					lookup_extensions=','.join(config_file_exts),
					page_count=4,
					scan_history=scan_history
				)
				if res is _GOOFUZZ_BLOCKED: google_blocked = True
				else: results += res or []

			elif dork == 'jenkins' :
				lookup_keyword = 'Jenkins'
				res = get_and_save_dork_results(
					lookup_target=host,
					results_dir=results_dir,
					type=dork,
					lookup_keywords=lookup_keyword,
					page_count=1,
					scan_history=scan_history
				)
				if res is _GOOFUZZ_BLOCKED: google_blocked = True
				else: results += res or []

			elif dork == 'wordpress_files' :
				lookup_keywords = [
					'/wp-content/',
					'/wp-includes/'
				]
				res = get_and_save_dork_results(
					lookup_target=host,
					results_dir=results_dir,
					type=dork,
					lookup_keywords=','.join(lookup_keywords),
					page_count=5,
					scan_history=scan_history
				)
				if res is _GOOFUZZ_BLOCKED: google_blocked = True
				else: results += res or []

			elif dork == 'php_error' :
				lookup_keywords = [
					'PHP Parse error',
					'PHP Warning',
					'PHP Error'
				]
				res = get_and_save_dork_results(
					lookup_target=host,
					results_dir=results_dir,
					type=dork,
					lookup_keywords=','.join(lookup_keywords),
					page_count=5,
					scan_history=scan_history
				)
				if res is _GOOFUZZ_BLOCKED: google_blocked = True
				else: results += res or []

			elif dork == 'exposed_documents' :
				docs_file_ext = [
					'doc',
					'docx',
					'odt',
					'pdf',
					'rtf',
					'sxw',
					'psw',
					'ppt',
					'pptx',
					'pps',
					'csv'
				]
				res = get_and_save_dork_results(
					lookup_target=host,
					results_dir=results_dir,
					type=dork,
					lookup_extensions=','.join(docs_file_ext),
					page_count=7,
					scan_history=scan_history
				)
				if res is _GOOFUZZ_BLOCKED: google_blocked = True
				else: results += res or []

			elif dork == 'db_files' :
				file_ext = [
					'sql',
					'db',
					'dbf',
					'mdb'
				]
				res = get_and_save_dork_results(
					lookup_target=host,
					results_dir=results_dir,
					type=dork,
					lookup_extensions=','.join(file_ext),
					page_count=1,
					scan_history=scan_history
				)
				if res is _GOOFUZZ_BLOCKED: google_blocked = True
				else: results += res or []

			elif dork == 'git_exposed' :
				file_ext = [
					'git',
				]
				res = get_and_save_dork_results(
					lookup_target=host,
					results_dir=results_dir,
					type=dork,
					lookup_extensions=','.join(file_ext),
					page_count=1,
					scan_history=scan_history
				)
				if res is _GOOFUZZ_BLOCKED: google_blocked = True
				else: results += res or []

	except Exception as e:
		logger.exception(e)

	if google_blocked:
		logger.warning('dorking(): Google blocked this IP \u2014 dorking aborted early. Configure and enable proxies in Settings > Proxy to avoid blocks.')

	return results


@app.task(name='theHarvester', queue='theHarvester_queue', bind=False)
def theHarvester(config, host, scan_history_id, activity_id, results_dir, ctx=None):
	if ctx is None:
		ctx = {}
	"""Run theHarvester to get save emails, hosts, employees found in domain.

	Args:
		config (dict): yaml_configuration
		host (str): target name
		scan_history_id (startScan.ScanHistory): Scan History ID
		activity_id: ScanActivity ID
		results_dir (str): Path to store scan results
		ctx (dict): context of scan

	Returns:
		dict: Dict of emails, employees, hosts and ips found during crawling.
	"""
	scan_history = ScanHistory.objects.get(pk=scan_history_id)
	enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
	output_path_json = f'{results_dir}/theHarvester.json'
	theHarvester_dir = '/usr/src/github/theHarvester'
	history_file = f'{results_dir}/commands.txt'
	# CRT-01 fix: Validate and sanitize host before command interpolation
	if not validate_domain(host):
		logger.error(f'theHarvester: Invalid domain rejected: {repr(host[:100])}')
		return {}
	safe_host = sanitize_shell_arg(host)
	# Use only free/reliable sources — '-b all' tries API-key sources that fail and produce null output
	# bing included as it provides Bing email/subdomain intel and acts as Google-independent fallback
	harvester_sources = 'anubis,bing,certspotter,crtsh,dnsdumpster,hackertarget,otx,rapiddns,subdomaincenter,urlscan,yahoo'
	cmd  = f'python3 {theHarvester_dir}/theHarvester.py -d {safe_host} -b {harvester_sources} -f {output_path_json}'

	# Update proxies.yaml
	proxy_query = Proxy.objects.all()
	if proxy_query.exists():
		proxy = proxy_query.first()
		if proxy.use_proxy:
			proxy_list = proxy.proxies.splitlines()
			yaml_data = {'http' : proxy_list}
			with open(f'{theHarvester_dir}/proxies.yaml', 'w') as file:
				yaml.dump(yaml_data, file)

	# Run cmd
	run_command(
		cmd,
		shell=False,
		cwd=theHarvester_dir,
		history_file=history_file,
		scan_id=scan_history_id,
		activity_id=activity_id)

	# Get file location
	if not os.path.isfile(output_path_json):
		logger.error(f'Could not open {output_path_json}')
		return {}

	# Load theHarvester results — handle null/empty output gracefully
	with open(output_path_json, 'r') as f:
		raw = f.read().strip()
	if not raw or raw in ('null', '[]', '{}', 'None'):
		logger.warning(f'theHarvester returned no results for {host}')
		return {}
	try:
		data = json.loads(raw)
	except json.JSONDecodeError as e:
		logger.error(f'theHarvester JSON parse error: {e}')
		return {}
	if not data or not isinstance(data, dict):
		logger.warning(f'theHarvester returned unexpected data type for {host}')
		return {}

	# Re-indent theHarvester JSON
	with open(output_path_json, 'w') as f:
		json.dump(data, f, indent=4)

	emails = data.get('emails', [])
	# Write emails.txt so h8mail can consume it after this task completes
	emails_file = f'{results_dir}/emails.txt'
	with open(emails_file, 'w') as ef:
		for addr in emails:
			ef.write(addr + '\n')
	logger.info(f'theHarvester: wrote {len(emails)} email(s) to {emails_file}')

	for email_address in emails:
		email, _ = save_email(email_address, scan_history=scan_history)
		# if email:
		# 	self.notify(fields={'Emails': f'• `{email.address}`'})

	linkedin_people = data.get('linkedin_people', [])
	for people in linkedin_people:
		employee, _ = save_employee(
			people,
			designation='linkedin',
			scan_history=scan_history)
		# if employee:
		# 	self.notify(fields={'LinkedIn people': f'• {employee.name}'})

	twitter_people = data.get('twitter_people', [])
	for people in twitter_people:
		employee, _ = save_employee(
			people,
			designation='twitter',
			scan_history=scan_history)
		# if employee:
		# 	self.notify(fields={'Twitter people': f'• {employee.name}'})

	hosts = data.get('hosts', [])
	urls = []
	for host in hosts:
		split = tuple(host.split(':'))
		http_url = split[0]
		subdomain_name = get_subdomain_from_url(http_url)
		subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)
		endpoint, _ = save_endpoint(
			http_url,
			crawl=False,
			ctx=ctx,
			subdomain=subdomain)
		# if endpoint:
		# 	urls.append(endpoint.http_url)
			# self.notify(fields={'Hosts': f'• {endpoint.http_url}'})

	# if enable_http_crawl:
	# 	ctx['track'] = False
	# 	http_crawl(urls, ctx=ctx)

	# TODO: Lots of ips unrelated with our domain are found, disabling
	# this for now.
	# ips = data.get('ips', [])
	# for ip_address in ips:
	# 	ip, created = save_ip_address(
	# 		ip_address,
	# 		subscan=subscan)
	# 	if ip:
	# 		send_task_notif.delay(
	# 			'osint',
	# 			scan_history_id=scan_history_id,
	# 			subscan_id=subscan_id,
	# 			severity='success',
	# 			update_fields={'IPs': f'{ip.address}'})
	return data


@app.task(name='h8mail', queue='h8mail_queue', bind=False)
def h8mail(config, host, scan_history_id, activity_id, results_dir, ctx=None):
	if ctx is None:
		ctx = {}
	"""Run h8mail.

	Args:
		config (dict): yaml_configuration
		host (str): target name
		scan_history_id (startScan.ScanHistory): Scan History ID
		activity_id: ScanActivity ID
		results_dir (str): Path to store scan results
		ctx (dict): context of scan

	Returns:
		list[dict]: List of credentials info.
	"""
	logger.warning('Getting leaked credentials')
	scan_history = ScanHistory.objects.get(pk=scan_history_id)
	input_path = f'{results_dir}/emails.txt'
	output_file = f'{results_dir}/h8mail.json'
	history_file = f'{results_dir}/commands.txt'

	# Skip if emails.txt is missing or empty (theHarvester found no emails)
	if not os.path.isfile(input_path) or os.path.getsize(input_path) == 0:
		logger.warning(f'h8mail: {input_path} is empty or missing — skipping credential check')
		return []

	cmd = f'h8mail -t {input_path} --json {output_file}'
	run_command(
		cmd,
		history_file=history_file,
		scan_id=scan_history_id,
		activity_id=activity_id)

	if not os.path.isfile(output_file):
		logger.warning('h8mail: output file not created — no breach results')
		return []

	try:
		with open(output_file) as f:
			data = json.load(f)
	except (json.JSONDecodeError, OSError) as e:
		logger.error(f'h8mail: failed to parse output: {e}')
		return []

	creds = data.get('targets', [])

	# TODO: go through h8mail output and save emails to DB
	for cred in creds:
		logger.warning(cred)
		email_address = cred['target']
		pwn_num = cred['pwn_num']
		pwn_data = cred.get('data', [])
		email, created = save_email(email_address, scan_history=scan_history)
		# if email:
		# 	self.notify(fields={'Emails': f'• `{email.address}`'})
	return creds


@app.task(name='screenshot', queue='main_scan_queue', base=ParaKangTask, bind=True)
def screenshot(self, ctx=None, description=None):
	if ctx is None:
		ctx = {}
	"""Uses EyeWitness to gather screenshot of a domain and/or url.

	Args:
		description (str, optional): Task description shown in UI.
	"""

	# Config
	screenshots_path = f'{self.results_dir}/screenshots'
	output_path = f'{self.results_dir}/screenshots/{self.filename}'
	alive_endpoints_file = f'{self.results_dir}/endpoints_alive.txt'
	config = self.yaml_configuration.get(SCREENSHOT) or {}
	enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
	intensity = config.get(INTENSITY) or self.yaml_configuration.get(INTENSITY, DEFAULT_SCAN_INTENSITY)
	timeout = config.get(TIMEOUT) or self.yaml_configuration.get(TIMEOUT, DEFAULT_HTTP_TIMEOUT + 5)
	threads = config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)

	# If intensity is normal, grab only the root endpoints of each subdomain
	strict = True if intensity == 'normal' else False

	# Get URLs to take screenshot of
	get_http_urls(
		is_alive=enable_http_crawl,
		strict=strict,
		write_filepath=alive_endpoints_file,
		get_only_default_urls=True,
		ctx=ctx
	)

	# Send start notif
	notification = Notification.objects.first()
	send_output_file = notification.send_scan_output_file if notification else False

	# Run cmd
	cmd = f'python3 /usr/src/github/EyeWitness/Python/EyeWitness.py -f {alive_endpoints_file} -d {screenshots_path} --no-prompt'
	cmd += f' --timeout {timeout}' if timeout > 0 else ''
	cmd += f' --threads {threads}' if threads > 0 else ''
	run_command(
		cmd,
		shell=False,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id)
	if not os.path.isfile(output_path):
		logger.error(f'Could not load EyeWitness results at {output_path} for {self.domain.name}.')
		return

	# Loop through results and save objects in DB
	screenshot_paths = []
	required_cols = [
		'Protocol',
		'Port',
		'Domain',
		'Request Status',
		'Screenshot Path'
	]
	with open(output_path, 'r', newline='') as file:
		reader = csv.DictReader(file)
		for row in reader:
			parsed_row = {col: row[col] for col in required_cols if col in row}
			protocol = parsed_row['Protocol']
			port = parsed_row['Port']
			subdomain_name = parsed_row['Domain']
			status = parsed_row['Request Status']
			screenshot_path = parsed_row['Screenshot Path']
			logger.info(f'{protocol}:{port}:{subdomain_name}:{status}')
			subdomain_query = Subdomain.objects.filter(name=subdomain_name)
			if self.scan:
				subdomain_query = subdomain_query.filter(scan_history=self.scan)
			if status == 'Successful' and subdomain_query.exists():
				subdomain = subdomain_query.first()
				screenshot_paths.append(screenshot_path)
				subdomain.screenshot_path = screenshot_path.replace('/usr/src/scan_results/', '')
				subdomain.save()
				logger.warning(f'Added screenshot for {subdomain.name} to DB')

	# Remove all db, html extra files in screenshot results
	run_command(
		f'rm -rf {screenshots_path}/*.csv {screenshots_path}/*.db {screenshots_path}/*.js {screenshots_path}/*.html {screenshots_path}/*.css',
		shell=True,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id)
	run_command(
		f'rm -rf {screenshots_path}/source',
		shell=True,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id)

	# Send finish notifs
	screenshots_str = '• ' + '\n• '.join([f'`{path}`' for path in screenshot_paths])
	self.notify(fields={'Screenshots': screenshots_str})
	if send_output_file:
		for path in screenshot_paths:
			title = get_output_file_name(
				self.scan_id,
				self.subscan_id,
				self.filename)
			send_file_to_discord.delay(path, title)


@app.task(name='port_scan', queue='main_scan_queue', base=ParaKangTask, bind=True)
def port_scan(self, hosts=None, ctx=None, description=None):
	if hosts is None:
		hosts = []
	if ctx is None:
		ctx = {}
	"""Run port scan.

	Args:
		hosts (list, optional): Hosts to run port scan on.
		description (str, optional): Task description shown in UI.

	Returns:
		list: List of open ports (dict).
	"""
	input_file = f'{self.results_dir}/input_subdomains_port_scan.txt'
	proxy = get_random_proxy(proxy_mode=self.proxy_mode)

	# Config
	config = self.yaml_configuration.get(PORT_SCAN) or {}
	enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
	timeout = config.get(TIMEOUT) or self.yaml_configuration.get(TIMEOUT, DEFAULT_HTTP_TIMEOUT)
	exclude_ports = config.get(NAABU_EXCLUDE_PORTS, [])
	exclude_subdomains = config.get(NAABU_EXCLUDE_SUBDOMAINS, False)
	ports = config.get(PORTS, NAABU_DEFAULT_PORTS)
	ports = [str(port) for port in ports]
	rate_limit = config.get(NAABU_RATE) or self.yaml_configuration.get(RATE_LIMIT, DEFAULT_RATE_LIMIT)
	threads = config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
	passive = config.get(NAABU_PASSIVE, False)
	use_naabu_config = config.get(USE_NAABU_CONFIG, False)
	exclude_ports_str = ','.join(return_iterable(exclude_ports))
	# nmap args
	nmap_enabled = config.get(ENABLE_NMAP, False)
	nmap_cmd = config.get(NMAP_COMMAND, '')
	nmap_script = config.get(NMAP_SCRIPT, '')
	nmap_script = ','.join(return_iterable(nmap_script))
	nmap_script_args = config.get(NMAP_SCRIPT_ARGS)

	if hosts:
		with open(input_file, 'w') as f:
			f.write('\n'.join(hosts))
	else:
		hosts = get_subdomains(
			write_filepath=input_file,
			exclude_subdomains=exclude_subdomains,
			ctx=ctx)

	# Build cmd
	cmd = 'naabu -json -exclude-cdn'
	cmd += f' -list {input_file}' if len(hosts) > 0 else f' -host {hosts[0]}'
	if 'full' in ports or 'all' in ports:
		ports_str = ' -p "-"'
	elif 'top-100' in ports:
		ports_str = ' -top-ports 100'
	elif 'top-1000' in ports:
		ports_str = ' -top-ports 1000'
	else:
		ports_str = ','.join(ports)
		ports_str = f' -p {ports_str}'
	cmd += ports_str
	cmd += ' -config /root/.config/naabu/config.yaml' if use_naabu_config else ''
	cmd += f' -proxy "{proxy}"' if proxy else ''
	cmd += f' -c {threads}' if threads else ''
	cmd += f' -rate {rate_limit}' if rate_limit > 0 else ''
	cmd += f' -timeout {timeout}s' if timeout > 0 else ''
	cmd += f' -passive' if passive else ''
	cmd += f' -exclude-ports {exclude_ports_str}' if exclude_ports else ''
	cmd += f' -silent'

	# Execute cmd and gather results
	results = []
	urls = []
	ports_data = {}
	for line in stream_command(
			cmd,
			shell=True,
			history_file=self.history_file,
			scan_id=self.scan_id,
			activity_id=self.activity_id):

		if not isinstance(line, dict):
			continue
		results.append(line)
		port_number = line['port']
		ip_address = line['ip']
		host = line.get('host') or ip_address
		if port_number == 0:
			continue

		# Grab subdomain
		subdomain = Subdomain.objects.filter(
			name=host,
			target_domain=self.domain,
			scan_history=self.scan
		).first()

		# Add IP DB
		ip, _ = save_ip_address(ip_address, subdomain, subscan=self.subscan)
		if ip:
			if self.subscan:
				ip.ip_subscan_ids.add(self.subscan)
				ip.save()
		# port 80 and 443 not needed as http crawl already does that.
		if port_number not in [80, 443]:
			http_url = f'{host}:{port_number}'
			endpoint, _ = save_endpoint(
				http_url,
				crawl=enable_http_crawl,
				ctx=ctx,
				subdomain=subdomain)
			if endpoint:
				http_url = endpoint.http_url
			urls.append(http_url)

		# Add Port in DB
		res = get_port_service_description(port_number)
		# get or create port
		port, created = update_or_create_port(
			port_number=port_number,
			service_name=res.get('service_name', ''),
			description=res.get('description', '')
		)

		if created:
			logger.warning(f'Added new port {port_number} to DB')

		if port_number in UNCOMMON_WEB_PORTS:
			port.is_uncommon = True
			port.save()
		ip.ports.add(port)
		ip.save()
		if host in ports_data:
			ports_data[host].append(port_number)
		else:
			ports_data[host] = [port_number]

		# Send notification
		logger.warning(f'Found opened port {port_number} on {ip_address} ({host})')

	if len(ports_data) == 0:
		logger.info('Finished running naabu port scan - No open ports found.')
		if nmap_enabled:
			logger.info('Nmap scans skipped')
		return ports_data

	# Send notification
	fields_str = ''
	for host, ports in ports_data.items():
		ports_str = ', '.join([f'`{port}`' for port in ports])
		fields_str += f'• `{host}`: {ports_str}\n'
	self.notify(fields={'Ports discovered': fields_str})

	# Save output to file
	with open(self.output_path, 'w') as f:
		json.dump(results, f, indent=4)

	logger.info('Finished running naabu port scan.')

	# Process nmap results: 1 process per host
	sigs = []
	if nmap_enabled:
		logger.warning(f'Starting nmap scans ...')
		logger.warning(ports_data)
		for host, port_list in ports_data.items():
			ports_str = '_'.join([str(p) for p in port_list])
			ctx_nmap = ctx.copy()
			ctx_nmap['description'] = get_task_title(f'nmap_{host}', self.scan_id, self.subscan_id)
			ctx_nmap['track'] = False
			sig = nmap.si(
				cmd=nmap_cmd,
				ports=port_list,
				host=host,
				script=nmap_script,
				script_args=nmap_script_args,
				max_rate=rate_limit,
				ctx=ctx_nmap)
			sigs.append(sig)
		task = group(sigs).apply_async()
		with allow_join_result():
			try:
				results = task.get()
			except ChordError as e:
				logger.warning(f'port_scan nmap: chord aborted (scan likely stopped): {e}')
				results = []

	return ports_data


@app.task(name='nmap', queue='main_scan_queue', base=ParaKangTask, bind=True)
def nmap(
		self,
		cmd=None,
		ports=[],
		host=None,
		input_file=None,
		script=None,
		script_args=None,
		max_rate=None,
		ctx={},
		description=None):
	"""Run nmap on a host.

	Args:
		cmd (str, optional): Existing nmap command to complete.
		ports (list, optional): List of ports to scan.
		host (str, optional): Host to scan.
		input_file (str, optional): Input hosts file.
		script (str, optional): NSE script to run.
		script_args (str, optional): NSE script args.
		max_rate (int): Max rate.
		description (str, optional): Task description shown in UI.
	"""
	notif = Notification.objects.first()
	ports_str = ','.join(str(port) for port in ports)
	self.filename = self.filename.replace('.txt', '.xml')
	filename_vulns = self.filename.replace('.xml', '_vulns.json')
	output_file = self.output_path
	output_file_xml = f'{self.results_dir}/{host}_{self.filename}'
	vulns_file = f'{self.results_dir}/{host}_{filename_vulns}'
	logger.warning(f'Running nmap on {host}:{ports}')

	# Build cmd
	nmap_cmd = get_nmap_cmd(
		cmd=cmd,
		ports=ports_str,
		script=script,
		script_args=script_args,
		max_rate=max_rate,
		host=host,
		input_file=input_file,
		output_file=output_file_xml)
	
	if not nmap_cmd:
		logger.error('Could not build nmap command')
		return

	# Run cmd
	run_command(
		nmap_cmd,
		shell=True,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id)

	# Get nmap XML results and convert to JSON
	vulns = parse_nmap_results(output_file_xml, output_file)
	with open(vulns_file, 'w') as f:
		json.dump(vulns, f, indent=4)

	# Save vulnerabilities found by nmap
	vulns_str = ''
	for vuln_data in vulns:
		# URL is not necessarily an HTTP URL when running nmap (can be any
		# other vulnerable protocols). Look for existing endpoint and use its
		# URL as vulnerability.http_url if it exists.
		url = vuln_data['http_url']
		endpoint = EndPoint.objects.filter(http_url__contains=url).first()
		if endpoint:
			vuln_data['http_url'] = endpoint.http_url
		vuln, created = save_vulnerability(
			target_domain=self.domain,
			subdomain=self.subdomain,
			scan_history=self.scan,
			subscan=self.subscan,
			endpoint=endpoint,
			**vuln_data)
		vulns_str += f'• {str(vuln)}\n'
		if created:
			logger.warning(str(vuln))

	# Send only 1 notif for all vulns to reduce number of notifs
	if notif and notif.send_vuln_notif and vulns_str:
		logger.warning(vulns_str)
		self.notify(fields={'CVEs': vulns_str})
	return vulns


@app.task(name='waf_detection', queue='main_scan_queue', base=ParaKangTask, bind=True)
def waf_detection(self, ctx=None, description=None):
	if ctx is None:
		ctx = {}
	"""
	Uses wafw00f to check for the presence of a WAF.

	Args:
		description (str, optional): Task description shown in UI.

	Returns:
		list: List of startScan.models.Waf objects.
	"""
	input_path = f'{self.results_dir}/input_endpoints_waf_detection.txt'
	config = self.yaml_configuration.get(WAF_DETECTION) or {}
	enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)

	# Get alive endpoints from DB
	get_http_urls(
		is_alive=enable_http_crawl,
		write_filepath=input_path,
		get_only_default_urls=True,
		ctx=ctx
	)

	cmd = f'wafw00f -i {input_path} -o {self.output_path}'
	run_command(
		cmd,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id)
	if not os.path.isfile(self.output_path):
		logger.error(f'Could not find {self.output_path}')
		return

	with open(self.output_path) as file:
		wafs = file.readlines()

	for line in wafs:
		line = " ".join(line.split())
		splitted = line.split(' ', 1)
		waf_info = splitted[1].strip()
		waf_name = waf_info[:waf_info.find('(')].strip()
		waf_manufacturer = waf_info[waf_info.find('(')+1:waf_info.find(')')].strip().replace('.', '')
		http_url = sanitize_url(splitted[0].strip())
		if not waf_name or waf_name == 'None':
			continue

		# Add waf to db
		waf, _ = Waf.objects.get_or_create(
			name=waf_name,
			manufacturer=waf_manufacturer
		)

		# Add waf info to Subdomain in DB
		subdomain = get_subdomain_from_url(http_url)
		logger.info(f'Wafw00f Subdomain : {subdomain}')
		subdomain_query, _ = Subdomain.objects.get_or_create(scan_history=self.scan, name=subdomain)
		subdomain_query.waf.add(waf)
		subdomain_query.save()
	return wafs


@app.task(name='dir_file_fuzz', queue='main_scan_queue', base=ParaKangTask, bind=True)
def dir_file_fuzz(self, ctx=None, description=None):
	if ctx is None:
		ctx = {}
	"""Perform directory scan, and currently uses `ffuf` as a default tool.

	Args:
		description (str, optional): Task description shown in UI.

	Returns:
		list: List of URLs discovered.
	"""
	# Config
	cmd = 'ffuf'
	config = self.yaml_configuration.get(DIR_FILE_FUZZ) or {}
	custom_headers = self.yaml_configuration.get(CUSTOM_HEADERS, [])
	# support for custom header will be remove in next major release, as of now it will be supported
	# for backward compatibility
	custom_header = self.yaml_configuration.get(CUSTOM_HEADER)
	if custom_header:
		custom_headers.append(custom_header)
	auto_calibration = config.get(AUTO_CALIBRATION, True)
	enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
	rate_limit = config.get(RATE_LIMIT) or self.yaml_configuration.get(RATE_LIMIT, DEFAULT_RATE_LIMIT)
	extensions = config.get(EXTENSIONS, DEFAULT_DIR_FILE_FUZZ_EXTENSIONS)
	# prepend . on extensions and deduplicate while preserving order
	seen_ext = set()
	unique_extensions = []
	for ext in extensions:
		ext = ext if ext.startswith('.') else '.' + ext
		if ext.lower() not in seen_ext:
			seen_ext.add(ext.lower())
			unique_extensions.append(ext)
	extensions_str = ','.join(unique_extensions)
	follow_redirect = config.get(FOLLOW_REDIRECT, FFUF_DEFAULT_FOLLOW_REDIRECT)
	max_time = config.get(MAX_TIME, 0)
	# Safety net: if no max_time set and recursion enabled, cap per-URL time
	max_time_per_url = config.get('max_time_per_url', 600)  # 10 min default per URL
	match_http_status = config.get(MATCH_HTTP_STATUS, FFUF_DEFAULT_MATCH_HTTP_STATUS)
	mc = ','.join([str(c) for c in match_http_status])
	recursive_level = config.get(RECURSIVE_LEVEL, FFUF_DEFAULT_RECURSIVE_LEVEL)
	stop_on_error = config.get(STOP_ON_ERROR, False)
	timeout = config.get(TIMEOUT) or self.yaml_configuration.get(TIMEOUT, DEFAULT_HTTP_TIMEOUT)
	threads = config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
	wordlist_name = config.get(WORDLIST, 'dicc')
	# Use ffuf's native -rate flag (requests/sec) instead of broken -p delay formula.
	# Old formula: delay = rate_limit / (threads * 100) produced 0.05s pause per request
	# which is self-contradictory with the intended rate_limit.
	# -rate is the correct way to limit total requests per second in ffuf.
	input_path = f'{self.results_dir}/input_dir_file_fuzz.txt'

	# Log estimated request count for visibility
	ext_count = len(unique_extensions)
	logger.info(
		f'[dir_file_fuzz] Estimated requests per URL: '
		f'wordlist × (1 + {ext_count} extensions) = multiplied by recursion depth {recursive_level}. '
		f'Threads: {threads}, Rate limit: {rate_limit} req/s'
	)

	# Get wordlist
	wordlist_name = 'dicc' if wordlist_name == 'default' else wordlist_name
	wordlist_path = f'/usr/src/wordlist/{wordlist_name}.txt'

	# Build command
	cmd += f' -w {wordlist_path}'
	cmd += f' -e {extensions_str}' if extensions else ''
	if max_time > 0:
		cmd += f' -maxtime {max_time}'
	elif max_time_per_url > 0:
		# Apply per-URL time cap as safety net against runaway recursion
		cmd += f' -maxtime {max_time_per_url}'
	# Use -rate (requests/second) instead of -p (delay per request).
	# -rate is the proper way to control throughput in ffuf.
	if rate_limit and rate_limit > 0:
		cmd += f' -rate {rate_limit}'
	cmd += f' -recursion -recursion-depth {recursive_level} ' if recursive_level > 0 else ''
	cmd += f' -t {threads}' if threads and threads > 0 else ''
	cmd += f' -timeout {timeout}' if timeout and timeout > 0 else ''
	cmd += ' -se' if stop_on_error else ''
	cmd += ' -fr' if follow_redirect else ''
	cmd += ' -ac' if auto_calibration else ''
	cmd += f' -mc {mc}' if mc else ''
	formatted_headers = ' '.join(f'-H "{header}"' for header in custom_headers)
	if formatted_headers:
		cmd += formatted_headers

	# Grab URLs to fuzz
	urls = get_http_urls(
		is_alive=True,
		ignore_files=False,
		write_filepath=input_path,
		get_only_default_urls=True,
		ctx=ctx
	)
	logger.warning(urls)

	# Loop through URLs and run command
	results = []
	discovered_urls = []  # collect ffuf-discovered URLs for post-crawl
	for url in urls:
		'''
			Above while fetching urls, we are not ignoring files, because some
			default urls may redirect to https://example.com/login.php
			so, ignore_files is set to False
			but, during fuzzing, we will only need part of the path, in above example
			it is still a good idea to ffuf base url https://example.com
			so files from base url
		'''
		url_parse = urlparse(url)
		url = url_parse.scheme + '://' + url_parse.netloc
		url += '/FUZZ' # TODO: fuzz not only URL but also POST / PUT / headers
		proxy = get_random_proxy(proxy_mode=self.proxy_mode)

		# Build final cmd
		fcmd = cmd
		fcmd += f' -x {proxy}' if proxy else ''
		fcmd += f' -u {url} -json'

		# Initialize DirectoryScan object
		dirscan = DirectoryScan()
		dirscan.scanned_date = timezone.now()
		dirscan.command_line = fcmd
		dirscan.save()

		# Loop through results and populate EndPoint and DirectoryFile in DB
		for line in stream_command(
				fcmd,
				shell=True,
				history_file=self.history_file,
				scan_id=self.scan_id,
				activity_id=self.activity_id):

			# Empty line, continue to the next record
			if not isinstance(line, dict):
				continue

			# Append line to results
			results.append(line)

			# Retrieve FFUF output
			url = line['url']
			# Extract path and convert to base64 (need byte string encode & decode)
			name = base64.b64encode(extract_path_from_url(url).encode()).decode()
			length = line['length']
			status = line['status']
			words = line['words']
			lines = line['lines']
			content_type = line['content-type']
			duration = line['duration']

			# If name empty log error and continue
			if not name:
				logger.error(f'FUZZ not found for "{url}"')
				continue

			# Get or create endpoint from URL
			endpoint, created = save_endpoint(url, crawl=False, ctx=ctx)

			# Continue to next line if endpoint returned is None
			if endpoint is None:
				continue

			# Track newly discovered URL for post-crawl
			if created:
				discovered_urls.append(endpoint.http_url)

			# Save endpoint data from FFUF output
			endpoint.http_status = status
			endpoint.content_length = length
			endpoint.response_time = duration / 1000000000
			endpoint.content_type = content_type
			endpoint.content_length = length
			endpoint.save()

			# Save directory file output from FFUF output
			dfile, created = DirectoryFile.objects.get_or_create(
				name=name,
				length=length,
				words=words,
				lines=lines,
				content_type=content_type,
				url=url,
				http_status=status)

			# Log newly created file or directory if debug activated
			if created and DEBUG:
				logger.warning(f'Found new directory or file {url}')

			# Add file to current dirscan
			dirscan.directory_files.add(dfile)

			# Add subscan relation to dirscan if exists
			if self.subscan:
				dirscan.dir_subscan_ids.add(self.subscan)

			# Save dirscan datas
			dirscan.save()

			# Get subdomain and add dirscan
			if ctx.get('subdomain_id', 0) > 0:
				subdomain = Subdomain.objects.filter(id=ctx['subdomain_id']).first()
			else:
				subdomain_name = get_subdomain_from_url(endpoint.http_url)
				subdomain = Subdomain.objects.filter(name=subdomain_name, scan_history=self.scan).first()
			if subdomain:
				subdomain.directories.add(dirscan)
				subdomain.save()
			else:
				logger.warning(f'dir_file_fuzz: subdomain not found for {endpoint.http_url}, skipping dir link')

	# Crawl newly discovered URLs (those found by ffuf, not the input URLs)
	if enable_http_crawl and discovered_urls:
		ctx['track'] = False
		http_crawl(discovered_urls, ctx=ctx)

	return results


@app.task(name='fetch_url', queue='main_scan_queue', base=ParaKangTask, bind=True)
def fetch_url(self, urls=None, ctx=None, description=None):
	if urls is None:
		urls = []
	if ctx is None:
		ctx = {}
	"""Fetch URLs using different tools like gauplus, gau, gospider, waybackurls ...

	Args:
		urls (list): List of URLs to start from.
		description (str, optional): Task description shown in UI.
	"""
	input_path = f'{self.results_dir}/input_endpoints_fetch_url.txt'
	proxy = get_random_proxy(proxy_mode=self.proxy_mode)

	# Config
	config = self.yaml_configuration.get(FETCH_URL) or {}
	should_remove_duplicate_endpoints = config.get(REMOVE_DUPLICATE_ENDPOINTS, True)
	duplicate_removal_fields = config.get(DUPLICATE_REMOVAL_FIELDS, ENDPOINT_SCAN_DEFAULT_DUPLICATE_FIELDS)
	enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
	gf_patterns = config.get(GF_PATTERNS, DEFAULT_GF_PATTERNS)
	ignore_file_extension = config.get(IGNORE_FILE_EXTENSION, DEFAULT_IGNORE_FILE_EXTENSIONS)
	tools = config.get(USES_TOOLS, ENDPOINT_SCAN_DEFAULT_TOOLS)
	threads = config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
	# domain_request_headers = self.domain.request_headers if self.domain else None
	custom_headers = self.yaml_configuration.get(CUSTOM_HEADERS, [])
	'''
	# TODO: Remove custom_header in next major release
		support for custom_header will be remove in next major release, 
		as of now it will be supported for backward compatibility
		only custom_headers will be supported
	'''
	custom_header = self.yaml_configuration.get(CUSTOM_HEADER)
	if custom_header:
		custom_headers.append(custom_header)
	exclude_subdomains = config.get(EXCLUDED_SUBDOMAINS, False)

	# Get URLs to scan and save to input file
	if urls:
		with open(input_path, 'w') as f:
			f.write('\n'.join(urls))
	else:
		urls = get_http_urls(
			is_alive=enable_http_crawl,
			write_filepath=input_path,
			exclude_subdomains=exclude_subdomains,
			get_only_default_urls=True,
			ctx=ctx
		)

	# Domain regex
	host = self.domain.name if self.domain else urlparse(urls[0]).netloc
	host_regex = f"\'https?://([a-z0-9]+[.])*{host}.*\'"

	# Tools cmds
	cmd_map = {
		'gau': f'gau',
		'hakrawler': 'hakrawler -subs -u',
		'waybackurls': 'waybackurls',
		'gospider': f'gospider -S {input_path} --js -d 2 --sitemap --robots -w -r',
		'katana': f'katana -list {input_path} -silent -jc -kf all -d 3 -fs rdn',
	}
	if proxy:
		cmd_map['gau'] += f' --proxy "{proxy}"'
		cmd_map['gospider'] += f' -p {proxy}'
		cmd_map['hakrawler'] += f' -proxy {proxy}'
		cmd_map['katana'] += f' -proxy {proxy}'
	if threads > 0:
		cmd_map['gau'] += f' --threads {threads}'
		cmd_map['gospider'] += f' -t {threads}'
		cmd_map['katana'] += f' -c {threads}'
	if custom_headers:
		# gau, waybackurls does not support custom headers
		formatted_headers = ' '.join(f'-H "{header}"' for header in custom_headers)
		cmd_map['gospider'] += formatted_headers
		cmd_map['hakrawler'] += ';;'.join(header for header in custom_headers)
		cmd_map['katana'] += formatted_headers
	cat_input = f'cat {input_path}'
	grep_output = f'grep -Eo {host_regex}'
	max_urls_per_tool = 50000
	cmd_map = {
		tool: f'{cat_input} | {cmd} | {grep_output} | head -n {max_urls_per_tool} > {self.results_dir}/urls_{tool}.txt'
		for tool, cmd in cmd_map.items()
	}
	tasks = group(
		run_command.si(
			cmd,
			shell=True,
			scan_id=self.scan_id,
			activity_id=self.activity_id)
		for tool, cmd in cmd_map.items()
		if tool in tools
	)

	# Cleanup task
	sort_output = [
		f'cat {self.results_dir}/urls_* > {self.output_path}',
		f'cat {input_path} >> {self.output_path}',
		f'sort -u {self.output_path} -o {self.output_path}',
	]
	if ignore_file_extension:
		ignore_exts = '|'.join(ignore_file_extension)
		grep_ext_filtered_output = [
			f'cat {self.output_path} | grep -Eiv "\\.({ignore_exts}).*" > {self.results_dir}/urls_filtered.txt',
			f'mv {self.results_dir}/urls_filtered.txt {self.output_path}'
		]
		sort_output.extend(grep_ext_filtered_output)
	cleanup = chain(
		run_command.si(
			cmd,
			shell=True,
			scan_id=self.scan_id,
			activity_id=self.activity_id)
		for cmd in sort_output
	)

	# Run all commands
	task = chord(tasks)(cleanup)
	try:
		with allow_join_result():
			task.get()
	except ChordError as e:
		logger.warning(f'fetch_url: chord aborted (scan likely stopped): {e}')
		return None

	# Store all the endpoints and run httpx
	MAX_URLS = 200000
	with open(self.output_path) as f:
		discovered_urls = f.readlines()[:MAX_URLS]
		self.notify(fields={'Discovered URLs': len(discovered_urls)})

	# Some tools can have an URL in the format <URL>] - <PATH> or <URL> - <PATH>, add them
	# to the final URL list
	seen_urls = set()
	all_urls = []
	for url in discovered_urls:
		url = url.strip()
		if not url:
			continue
		urlpath = None
		base_url = None
		if '] ' in url: # found JS scraped endpoint e.g from gospider
			split = tuple(url.split('] '))
			if not len(split) == 2:
				logger.warning(f'URL format not recognized for "{url}". Skipping.')
				continue
			base_url, urlpath = split
			urlpath = urlpath.lstrip('- ')
		elif ' - ' in url: # found JS scraped endpoint e.g from gospider
			base_url, urlpath = tuple(url.split(' - '))

		if base_url and urlpath:
			subdomain = urlparse(base_url)
			url = f'{subdomain.scheme}://{subdomain.netloc}{self.starting_point_path}'

		if not validators.url(url):
			logger.warning(f'Invalid URL "{url}". Skipping.')
			continue

		if url not in seen_urls:
			seen_urls.add(url)
			all_urls.append(url)

	# Filter out URLs if a path filter was passed
	if self.starting_point_path:
		all_urls = [url for url in all_urls if self.starting_point_path in url]

	# if exclude_paths is found, then remove urls matching those paths
	if self.excluded_paths:
		all_urls = exclude_urls_by_patterns(self.excluded_paths, all_urls)

	# Write result to output path
	with open(self.output_path, 'w') as f:
		f.write('\n'.join(all_urls))
	logger.warning(f'Found {len(all_urls)} usable URLs')

	# Crawl discovered URLs
	if enable_http_crawl:
		ctx['track'] = False
		http_crawl(
			all_urls,
			ctx=ctx,
			should_remove_duplicate_endpoints=should_remove_duplicate_endpoints,
			duplicate_removal_fields=duplicate_removal_fields
		)


	#-------------------#
	# GF PATTERNS MATCH #
	#-------------------#

	# Combine old gf patterns with new ones
	if gf_patterns:
		self.scan.used_gf_patterns = ','.join(gf_patterns)
		self.scan.save()

	# Run gf patterns on saved endpoints
	# TODO: refactor to Celery task
	for gf_pattern in gf_patterns:
		# TODO: js var is causing issues, removing for now
		if gf_pattern == 'jsvar':
			logger.info('Ignoring jsvar as it is causing issues.')
			continue

		# Run gf on current pattern
		logger.warning(f'Running gf on pattern "{gf_pattern}"')
		gf_output_file = f'{self.results_dir}/gf_patterns_{gf_pattern}.txt'
		cmd = f'cat {self.output_path} | gf {gf_pattern} | grep -Eo {host_regex} >> {gf_output_file}'
		run_command(
			cmd,
			shell=True,
			history_file=self.history_file,
			scan_id=self.scan_id,
			activity_id=self.activity_id)

		# Check output file
		if not os.path.exists(gf_output_file):
			logger.error(f'Could not find GF output file {gf_output_file}. Skipping GF pattern "{gf_pattern}"')
			continue

		# Read output file line by line and
		with open(gf_output_file, 'r') as f:
			lines = f.readlines()

		# Add endpoints / subdomains to DB
		for url in lines:
			http_url = sanitize_url(url)
			subdomain_name = get_subdomain_from_url(http_url)
			subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)
			if not subdomain:
				continue
			endpoint, created = save_endpoint(
				http_url,
				crawl=False,
				subdomain=subdomain,
				ctx=ctx)
			if not endpoint:
				continue
			earlier_pattern = None
			if not created:
				earlier_pattern = endpoint.matched_gf_patterns
			pattern = f'{earlier_pattern},{gf_pattern}' if earlier_pattern else gf_pattern
			endpoint.matched_gf_patterns = pattern
			endpoint.save()

	return all_urls


def parse_curl_output(response):
	# TODO: Enrich from other cURL fields.
	CURL_REGEX_HTTP_STATUS = f'HTTP\/(?:(?:\d\.?)+)\s(\d+)\s(?:\w+)'
	http_status = 0
	if response:
		failed = False
		regex = re.compile(CURL_REGEX_HTTP_STATUS, re.MULTILINE)
		try:
			http_status = int(regex.findall(response)[0])
		except (KeyError, TypeError, IndexError):
			pass
	return {
		'http_status': http_status,
	}


@app.task(name='vulnerability_scan', queue='main_scan_queue', bind=True, base=ParaKangTask)
def vulnerability_scan(self, urls=None, ctx=None, description=None):
	if urls is None:
		urls = []
	if ctx is None:
		ctx = {}
	"""
		This function will serve as an entrypoint to vulnerability scan.
		All other vulnerability scan will be run from here including nuclei, crlfuzz, etc
	"""
	logger.info('Running Vulnerability Scan Queue')
	config = self.yaml_configuration.get(VULNERABILITY_SCAN) or {}
	should_run_nuclei = config.get(RUN_NUCLEI, True)
	should_run_crlfuzz = config.get(RUN_CRLFUZZ, False)
	should_run_dalfox = config.get(RUN_DALFOX, False)
	should_run_s3scanner = config.get(RUN_S3SCANNER, True)

	# Determine DAST label for timeline display
	nuclei_specific_config_pre = config.get('nuclei', {})
	_run_dast = nuclei_specific_config_pre.get('run_dast', False)
	_nuclei_desc = 'Nuclei Scan + DAST' if _run_dast else 'Nuclei Scan'

	grouped_tasks = []
	if should_run_nuclei:
		_task = nuclei_scan.si(
			urls=urls,
			ctx=ctx,
			description=_nuclei_desc
		)
		grouped_tasks.append(_task)

	if should_run_crlfuzz:
		_task = crlfuzz_scan.si(
			urls=urls,
			ctx=ctx,
			description=f'CRLFuzz Scan'
		)
		grouped_tasks.append(_task)

	if should_run_dalfox:
		_task = dalfox_xss_scan.si(
			urls=urls,
			ctx=ctx,
			description=f'Dalfox XSS Scan'
		)
		grouped_tasks.append(_task)

	if should_run_s3scanner:
		_task = s3scanner.si(
			ctx=ctx,
			description=f'Misconfigured S3 Buckets Scanner'
		)
		grouped_tasks.append(_task)

	# Run vulnerability tools SEQUENTIALLY (chain) instead of in parallel (group)
	# to prevent OOM on low-memory systems (e.g. 8GB laptops).
	# Each tool (nuclei, dalfox, crlfuzz, s3scanner) is heavy — running them
	# simultaneously causes 2-4x memory spike that kills the scan.
	if not grouped_tasks:
		logger.info('No vulnerability scan tools enabled, skipping.')
		return None

	celery_chain = chain(*grouped_tasks)
	job = celery_chain.apply_async()

	# MED-06 fix: Use allow_join_result() to permit job.get() inside a task.
	# Without this, Celery raises "Never call result.get() within a task!"
	# which causes vulnerability_scan to return prematurely while subtasks
	# (nuclei, dalfox, etc.) are still running, marking the scan as complete.
	try:
		with allow_join_result():
			job.get(timeout=14400, interval=5)
	except ChordError as e:
		logger.warning(f'Vulnerability scan: chord aborted (scan likely stopped): {e}')
	except Exception as e:
		logger.error(f'Vulnerability scan error or timeout: {e}')

	logger.info('Vulnerability scan completed...')

	# return results
	return None

@app.task(name='nuclei_individual_severity_module', queue='main_scan_queue', base=ParaKangTask, bind=True)
def nuclei_individual_severity_module(self, cmd, severity, enable_http_crawl, should_fetch_gpt_report, ctx=None, description=None):
	if ctx is None:
		ctx = {}
	'''
		This celery task will run vulnerability scan in parallel.
		All severities supplied should run in parallel as grouped tasks.
	'''
	results = []
	logger.info(f'Running vulnerability scan with severity: {severity}')
	cmd += f' -severity {severity}'
	# Send start notification
	notif = Notification.objects.first()
	send_status = notif.send_scan_status_notif if notif else False

	for line in stream_command(
			cmd,
			history_file=self.history_file,
			scan_id=self.scan_id,
			activity_id=self.activity_id):

		if not isinstance(line, dict):
			if isinstance(line, str) and ('[FTL]' in line or '[ERR]' in line or 'proxies are dead' in line):
				logger.warning(f'nuclei severity={severity}: {line.strip()}')
			continue

		results.append(line)

		# Gather nuclei results
		vuln_data = parse_nuclei_result(line)

		# Get corresponding subdomain
		http_url = sanitize_url(line.get('matched-at'))
		subdomain_name = get_subdomain_from_url(http_url)

		# TODO: this should be get only
		subdomain, _ = Subdomain.objects.get_or_create(
			name=subdomain_name,
			scan_history=self.scan,
			target_domain=self.domain
		)

		# Look for duplicate vulnerabilities by excluding records that might change but are irrelevant.
		object_comparison_exclude = ['response', 'curl_command', 'tags', 'references', 'cve_ids', 'cwe_ids']

		# Add subdomain and target domain to the duplicate check
		vuln_data_copy = vuln_data.copy()
		vuln_data_copy['subdomain'] = subdomain
		vuln_data_copy['target_domain'] = self.domain

		# Check if record exists, if exists do not save it
		if record_exists(Vulnerability, data=vuln_data_copy, exclude_keys=object_comparison_exclude):
			logger.warning(f'Nuclei vulnerability of severity {severity} : {vuln_data_copy["name"]} for {subdomain_name} already exists')
			continue

		# Get or create EndPoint object
		response = line.get('response')
		# Avoid duplicate httpx crawls: multiple nuclei severity tasks run in parallel
		# and all find the same URLs. Only crawl if endpoint not already in DB with HTTP status.
		existing_endpoint = EndPoint.objects.filter(
			http_url=http_url,
			scan_history=self.scan,
			http_status__isnull=False
		).first()
		httpx_crawl = False if (response or existing_endpoint) else enable_http_crawl
		endpoint, _ = save_endpoint(
			http_url,
			crawl=httpx_crawl,
			subdomain=subdomain,
			ctx=ctx)
		if endpoint:
			http_url = endpoint.http_url
			if not httpx_crawl:
				output = parse_curl_output(response)
				endpoint.http_status = output['http_status']
				endpoint.save()

		# Get or create Vulnerability object
		vuln, _ = save_vulnerability(
			target_domain=self.domain,
			http_url=http_url,
			scan_history=self.scan,
			subscan=self.subscan,
			subdomain=subdomain,
			**vuln_data)
		if not vuln:
			continue

		# Print vuln
		severity = line['info'].get('severity', 'unknown')
		logger.warning(str(vuln))


		# Send notification for all vulnerabilities except info
		url = vuln.http_url or vuln.subdomain
		send_vuln = (
			notif and
			notif.send_vuln_notif and
			vuln and
			severity in ['low', 'medium', 'high', 'critical'])
		if send_vuln:
			fields = {
				'Severity': f'**{severity.upper()}**',
				'URL': http_url,
				'Subdomain': subdomain_name,
				'Name': vuln.name,
				'Type': vuln.type,
				'Description': vuln.description,
				'Template': vuln.template_url,
				'Tags': vuln.get_tags_str(),
				'CVEs': vuln.get_cve_str(),
				'CWEs': vuln.get_cwe_str(),
				'References': vuln.get_refs_str()
			}
			severity_map = {
				'low': 'info',
				'medium': 'warning',
				'high': 'error',
				'critical': 'error'
			}
			self.notify(
				f'vulnerability_scan_#{vuln.id}',
				severity_map[severity],
				fields,
				add_meta_info=False)

		"""
			Send report to hackerone when
			1. send_report is True from Hackerone model in ScanEngine
			2. username and key is set in HackerOneAPIKey in Dashboard
			3. severity is not info or low
		"""
		hackerone_query = Hackerone.objects.filter(send_report=True)
		api_key_check_query = HackerOneAPIKey.objects.filter(
			Q(username__isnull=False) & Q(key__isnull=False)
		)

		send_report = (
			hackerone_query.exists() and
			api_key_check_query.exists() and
			severity not in ('info', 'low') and
			vuln.target_domain.h1_team_handle
		)

		if send_report:
			hackerone = hackerone_query.first()
			if hackerone.send_critical and severity == 'critical':
				send_hackerone_report.delay(vuln.id)
			elif hackerone.send_high and severity == 'high':
				send_hackerone_report.delay(vuln.id)
			elif hackerone.send_medium and severity == 'medium':
				send_hackerone_report.delay(vuln.id)

	# Write results to JSON file
	with open(self.output_path, 'w') as f:
		json.dump(results, f, indent=4)

	# Send finish notif
	if send_status:
		vulns = Vulnerability.objects.filter(scan_history__id=self.scan_id)
		info_count = vulns.filter(severity=0).count()
		low_count = vulns.filter(severity=1).count()
		medium_count = vulns.filter(severity=2).count()
		high_count = vulns.filter(severity=3).count()
		critical_count = vulns.filter(severity=4).count()
		unknown_count = vulns.filter(severity=-1).count()
		vulnerability_count = info_count + low_count + medium_count + high_count + critical_count + unknown_count
		fields = {
			'Total': vulnerability_count,
			'Critical': critical_count,
			'High': high_count,
			'Medium': medium_count,
			'Low': low_count,
			'Info': info_count,
			'Unknown': unknown_count
		}
		self.notify(fields=fields)

	# after vulnerability scan is done, we need to run LLM report if
	# should_fetch_gpt_report and either OpenAI key exists or Ollama is enabled
	ollama_settings = OllamaSettings.objects.first()
	use_ollama = ollama_settings and ollama_settings.use_ollama

	if should_fetch_gpt_report and (OpenAiAPIKey.objects.all().first() or use_ollama):
		logger.info('Getting Vulnerability LLM Report')
		vulns = Vulnerability.objects.filter(
			scan_history__id=self.scan_id
		).filter(
			source=NUCLEI
		).exclude(
			severity=0
		)
		# find all unique vulnerabilities based on path and title
		# all unique vulnerability will go thru gpt function and get report
		# once report is got, it will be matched with other vulnerabilities and saved
		unique_vulns = set()
		for vuln in vulns:
			unique_vulns.add((vuln.name, vuln.get_path()))

		unique_vulns = list(unique_vulns)

		# Ollama runs locally — limit concurrent LLM requests to avoid OOM.
		# OpenAI API can handle more parallelism than local Ollama.
		_llm_workers = 1 if use_ollama else min(DEFAULT_THREADS, 5)
		with concurrent.futures.ThreadPoolExecutor(max_workers=_llm_workers) as executor:
			future_to_gpt = {executor.submit(get_vulnerability_gpt_report, vuln): vuln for vuln in unique_vulns}

			# Wait for all tasks to complete
			for future in concurrent.futures.as_completed(future_to_gpt):
				gpt = future_to_gpt[future]
				try:
					future.result()
				except Exception as e:
					logger.error(f"Exception for Vulnerability {vuln}: {e}")

		return None


def get_vulnerability_gpt_report(vuln):
	title = vuln[0]
	path = vuln[1]
	if not path:
		path = '/'
	logger.info(f'Getting GPT Report for {title}, PATH: {path}')
	# check if in db already exists
	stored = GPTVulnerabilityReport.objects.filter(
		url_path=path
	).filter(
		title=title
	).first()
	if stored and stored.description and stored.impact and stored.remediation:
		response = {
			'description': stored.description,
			'impact': stored.impact,
			'remediation': stored.remediation,
			'references': [url.url for url in stored.references.all()]
		}
	else:
		report = LLMVulnerabilityReportGenerator(logger=logger)
		vulnerability_description = get_gpt_vuln_input_description(
			title,
			path
		)
		response = report.get_vulnerability_description(vulnerability_description)
		# Only save to DB if we got a valid response with actual content
		if response.get('status') and response.get('description'):
			add_gpt_description_db(
				title,
				path,
				response.get('description'),
				response.get('impact'),
				response.get('remediation'),
				response.get('references', [])
			)
		else:
			logger.warning(f'LLM failed for {title}: {response.get("error", "unknown error")}')
			return


	for vuln in Vulnerability.objects.filter(name=title, http_url__icontains=path):
		vuln.description = response.get('description', vuln.description)
		vuln.impact = response.get('impact')
		vuln.remediation = response.get('remediation')
		vuln.is_gpt_used = True
		vuln.save()

		for url in response.get('references', []):
			ref, created = VulnerabilityReference.objects.get_or_create(url=url)
			vuln.references.add(ref)
			vuln.save()


def add_gpt_description_db(title, path, description, impact, remediation, references):
	logger.info(f'Adding GPT Report to DB for {title}, PATH: {path}')
	if not path:
		path = '/'
	gpt_report = GPTVulnerabilityReport()
	gpt_report.url_path = path
	gpt_report.title = title
	gpt_report.description = description
	gpt_report.impact = impact
	gpt_report.remediation = remediation
	gpt_report.save()

	for url in references:
		ref, created = VulnerabilityReference.objects.get_or_create(url=url)
		gpt_report.references.add(ref)
		gpt_report.save()

@app.task(name='nuclei_scan', queue='main_scan_queue', base=ParaKangTask, bind=True)
def nuclei_scan(self, urls=None, ctx=None, description=None):
	if urls is None:
		urls = []
	if ctx is None:
		ctx = {}
	"""HTTP vulnerability scan using Nuclei

	Args:
		urls (list, optional): If passed, filter on those URLs.
		description (str, optional): Task description shown in UI.

	Notes:
	Unfurl the urls to keep only domain and path, will be sent to vuln scan and
	ignore certain file extensions. Thanks: https://github.com/six2dez/reconftw
	"""
	# Config
	config = self.yaml_configuration.get(VULNERABILITY_SCAN) or {}
	input_path = f'{self.results_dir}/input_endpoints_vulnerability_scan.txt'
	enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
	concurrency = config.get(NUCLEI_CONCURRENCY) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
	intensity = config.get(INTENSITY) or self.yaml_configuration.get(INTENSITY, DEFAULT_SCAN_INTENSITY)
	rate_limit = config.get(RATE_LIMIT) or self.yaml_configuration.get(RATE_LIMIT, DEFAULT_RATE_LIMIT)
	retries = config.get(RETRIES) or self.yaml_configuration.get(RETRIES, DEFAULT_RETRIES)
	timeout = config.get(TIMEOUT) or self.yaml_configuration.get(TIMEOUT, DEFAULT_HTTP_TIMEOUT)
	custom_headers = self.yaml_configuration.get(CUSTOM_HEADERS, [])
	'''
	# TODO: Remove custom_header in next major release
		support for custom_header will be remove in next major release, 
		as of now it will be supported for backward compatibility
		only custom_headers will be supported
	'''
	custom_header = self.yaml_configuration.get(CUSTOM_HEADER)
	if custom_header:
		custom_headers.append(custom_header)
	should_fetch_gpt_report = config.get(FETCH_GPT_REPORT, DEFAULT_GET_GPT_REPORT)
	# NOTE: nuclei/DAST tools run WITHOUT proxy intentionally.
	# Free proxies modify/buffer payloads which breaks vulnerability detection:
	# probing through a proxy that filters or alt-responds causes missed detections.
	# IP rotation is applied only in passive/discovery phases (subfinder, gau, dorking).
	nuclei_specific_config = config.get('nuclei', {})
	use_nuclei_conf = nuclei_specific_config.get(USE_NUCLEI_CONFIG, False)
	severities = nuclei_specific_config.get(NUCLEI_SEVERITY, NUCLEI_DEFAULT_SEVERITIES)
	tags = nuclei_specific_config.get(NUCLEI_TAGS, [])
	run_dast = nuclei_specific_config.get('run_dast', False)
	exclude_tags = nuclei_specific_config.get(NUCLEI_EXCLUDE_TAGS, [])
	exclude_templates = nuclei_specific_config.get(NUCLEI_EXCLUDE_TEMPLATES, [])
	tags = ','.join(tags)
	nuclei_templates = nuclei_specific_config.get(NUCLEI_TEMPLATE)
	custom_nuclei_templates = nuclei_specific_config.get(NUCLEI_CUSTOM_TEMPLATE)
	# severities_str = ','.join(severities)

	# Get alive endpoints
	if urls:
		with open(input_path, 'w') as f:
			f.write('\n'.join(urls))
	else:
		get_http_urls(
			is_alive=enable_http_crawl,
			ignore_files=True,
			write_filepath=input_path,
			ctx=ctx
		)

	if intensity == 'normal': # reduce number of endpoints to scan
		unfurl_filter = f'{self.results_dir}/urls_unfurled.txt'
		run_command(
			f"cat {input_path} | unfurl -u format %s://%d%p |uro > {unfurl_filter}",
			shell=True,
			history_file=self.history_file,
			scan_id=self.scan_id,
			activity_id=self.activity_id)
		run_command(
			f'sort -u {unfurl_filter} -o  {unfurl_filter}',
			shell=True,
			history_file=self.history_file,
			scan_id=self.scan_id,
			activity_id=self.activity_id)
		input_path = unfurl_filter

	# Build templates
	# logger.info('Updating Nuclei templates ...')
	run_command(
		'nuclei -update-templates',
		shell=True,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id)
	templates = []
	if not (nuclei_templates or custom_nuclei_templates):
		templates.append(NUCLEI_DEFAULT_TEMPLATES_PATH)

	if nuclei_templates:
		if ALL in nuclei_templates:
			template = NUCLEI_DEFAULT_TEMPLATES_PATH
			templates.append(template)
		else:
			templates.extend(nuclei_templates)

	if custom_nuclei_templates:
		custom_nuclei_template_paths = [f'{str(elem)}.yaml' for elem in custom_nuclei_templates]
		template = templates.extend(custom_nuclei_template_paths)

	# Add DAST templates (AI injection, CVE DAST all years, vulnerability DAST)
	# Use top-level dast/ subdirs — nuclei recurses into them automatically,
	# so all CVE years (2018, 2020, 2021, 2022, 2024, future) are included.
	if run_dast:
		dast_base = '/root/nuclei-templates/dast'
		dast_dirs = [
			f'{dast_base}/ai',
			f'{dast_base}/cves',
			f'{dast_base}/vulnerabilities',
		]
		import os as _os
		for d in dast_dirs:
			if _os.path.isdir(d):
				templates.append(d)
				# Count templates in this dir for clear logging
				tpl_count = sum(len(files) for _, _, files in _os.walk(d) if files)
				logger.info(f'nuclei_scan: added DAST templates dir {d} ({tpl_count} files)')
			else:
				logger.warning(f'nuclei_scan: DAST templates dir not found, skipping: {d}')

	# Build CMD
	cmd = 'nuclei -j'
	cmd += ' -config /root/.config/nuclei/config.yaml' if use_nuclei_conf else ''
	cmd += f' -irr'
	formatted_headers = ' '.join(f'-H "{header}"' for header in custom_headers)
	if formatted_headers:
		cmd += formatted_headers
	# NOTE: nuclei runs direct (no proxy) so payload delivery is not filtered.
	# Proxy-based IP rotation happens in passive/discovery phases only.
	cmd += f' -l {input_path}'
	cmd += f' -c {str(concurrency)}' if concurrency > 0 else ''
	cmd += f' -retries {retries}' if retries > 0 else ''
	cmd += f' -rl {rate_limit}' if rate_limit > 0 else ''
	# Enforce a minimum 10s timeout — DAST probes need more than the default 5s.
	effective_timeout = max(timeout, 10) if timeout and timeout > 0 else 10
	cmd += f' -timeout {str(effective_timeout)}'
	cmd += f' -tags {tags}' if tags else ''
	if exclude_tags:
		cmd += f' -etags {",".join(exclude_tags)}'
	if exclude_templates:
		for et in exclude_templates:
			cmd += f' -et {et}'
	cmd += f' -silent'
	for tpl in templates:
		cmd += f' -t {tpl}'


	grouped_tasks = []
	custom_ctx = ctx
	for severity in severities:
		custom_ctx['track'] = True
		_task = nuclei_individual_severity_module.si(
			cmd,
			severity,
			enable_http_crawl,
			should_fetch_gpt_report,
			ctx=custom_ctx,
			description=f'Nuclei Scan with severity {severity}'
		)
		grouped_tasks.append(_task)

	# Run severities SEQUENTIALLY (chain) instead of in parallel (group)
	# to prevent OOM: each nuclei process loads ~10,000+ templates into memory.
	# Running 6 severity processes simultaneously = 6x memory usage (~3-6 GB).
	# Sequential execution scans all severities with 1/6 the memory footprint.
	if not grouped_tasks:
		logger.info('No nuclei severities configured, skipping.')
		return None

	celery_chain = chain(*grouped_tasks)
	job = celery_chain.apply_async()

	# allow_join_result() is required here because nuclei_scan is itself a
	# Celery task and calling job.get() inside a task raises
	# "Never call result.get() within a task!" without this context manager.
	# (The allow_join_result() in vulnerability_scan does NOT propagate into
	# child tasks — each task that calls .get() must have its own guard.)
	try:
		with allow_join_result():
			job.get(timeout=14400, interval=5)
	except ChordError as e:
		logger.warning(f'nuclei_scan: chord aborted (scan likely stopped): {e}')
	except Exception as e:
		logger.error(f'Vulnerability scan with all severities error or timeout: {e}')

	logger.info('Vulnerability scan with all severities completed...')

	return None

@app.task(name='dalfox_xss_scan', queue='main_scan_queue', base=ParaKangTask, bind=True)
def dalfox_xss_scan(self, urls=None, ctx=None, description=None):
	if ctx is None:
		ctx = {}
	"""XSS Scan using dalfox

	Args:
		urls (list, optional): If passed, filter on those URLs.
		description (str, optional): Task description shown in UI.
	"""
	vuln_config = self.yaml_configuration.get(VULNERABILITY_SCAN) or {}
	should_fetch_gpt_report = vuln_config.get(FETCH_GPT_REPORT, DEFAULT_GET_GPT_REPORT)
	dalfox_config = vuln_config.get(DALFOX) or {}
	custom_headers = self.yaml_configuration.get(CUSTOM_HEADERS, [])
	'''
	# TODO: Remove custom_header in next major release
		support for custom_header will be remove in next major release, 
		as of now it will be supported for backward compatibility
		only custom_headers will be supported
	'''
	custom_header = self.yaml_configuration.get(CUSTOM_HEADER)
	if custom_header:
		custom_headers.append(custom_header)
	is_waf_evasion = dalfox_config.get(WAF_EVASION, False)
	blind_xss_server = dalfox_config.get(BLIND_XSS_SERVER)
	user_agent = dalfox_config.get(USER_AGENT) or self.yaml_configuration.get(USER_AGENT)
	timeout = dalfox_config.get(TIMEOUT)
	delay = dalfox_config.get(DELAY)
	threads = dalfox_config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
	input_path = f'{self.results_dir}/input_endpoints_dalfox_xss.txt'

	if urls:
		with open(input_path, 'w') as f:
			f.write('\n'.join(urls))
	else:
		get_http_urls(
			is_alive=False,
			ignore_files=False,
			write_filepath=input_path,
			ctx=ctx
		)

	notif = Notification.objects.first()
	send_status = notif.send_scan_status_notif if notif else False

	# command builder
	cmd = 'dalfox --silence --no-color --no-spinner'
	cmd += f' --only-poc r '
	cmd += f' --ignore-return 302,404,403'
	cmd += f' --skip-bav'
	cmd += f' file {input_path}'
	cmd += f' --waf-evasion' if is_waf_evasion else ''
	cmd += f' -b {blind_xss_server}' if blind_xss_server else ''
	cmd += f' --delay {delay}' if delay else ''
	cmd += f' --timeout {timeout}' if timeout else ''
	formatted_headers = ' '.join(f'-H "{header}"' for header in custom_headers)
	if formatted_headers:
		cmd += formatted_headers
	cmd += f' --user-agent {user_agent}' if user_agent else ''
	cmd += f' --worker {threads}' if threads else ''
	cmd += f' --format json'

	results = []
	for line in stream_command(
			cmd,
			history_file=self.history_file,
			scan_id=self.scan_id,
			activity_id=self.activity_id,
			trunc_char=','
		):
		if not isinstance(line, dict):
			continue

		results.append(line)

		vuln_data = parse_dalfox_result(line)

		http_url = sanitize_url(line.get('data'))
		subdomain_name = get_subdomain_from_url(http_url)

		# TODO: this should be get only
		subdomain, _ = Subdomain.objects.get_or_create(
			name=subdomain_name,
			scan_history=self.scan,
			target_domain=self.domain
		)
		endpoint, _ = save_endpoint(
			http_url,
			crawl=True,
			subdomain=subdomain,
			ctx=ctx
		)
		if endpoint:
			http_url = endpoint.http_url
			endpoint.save()

		vuln, _ = save_vulnerability(
			target_domain=self.domain,
			http_url=http_url,
			scan_history=self.scan,
			subscan=self.subscan,
			**vuln_data
		)

		if not vuln:
			continue

	# after vulnerability scan is done, we need to run LLM report if
	# should_fetch_gpt_report and either OpenAI key exists or Ollama is enabled
	ollama_settings = OllamaSettings.objects.first()
	use_ollama = ollama_settings and ollama_settings.use_ollama

	if should_fetch_gpt_report and (OpenAiAPIKey.objects.all().first() or use_ollama):
		logger.info('Getting Dalfox Vulnerability LLM Report')
		vulns = Vulnerability.objects.filter(
			scan_history__id=self.scan_id
		).filter(
			source=DALFOX
		).exclude(
			severity=0
		)

		_vulns = []
		for vuln in vulns:
			_vulns.append((vuln.name, vuln.http_url))

		_llm_workers = 1 if use_ollama else min(DEFAULT_THREADS, 5)
		with concurrent.futures.ThreadPoolExecutor(max_workers=_llm_workers) as executor:
			future_to_gpt = {executor.submit(get_vulnerability_gpt_report, vuln): vuln for vuln in _vulns}

			# Wait for all tasks to complete
			for future in concurrent.futures.as_completed(future_to_gpt):
				gpt = future_to_gpt[future]
				try:
					future.result()
				except Exception as e:
					logger.error(f"Exception for Vulnerability {vuln}: {e}")
	return results


@app.task(name='crlfuzz_scan', queue='main_scan_queue', base=ParaKangTask, bind=True)
def crlfuzz_scan(self, urls=None, ctx=None, description=None):
	"""CRLF Fuzzing with CRLFuzz

	Args:
		urls (list, optional): If passed, filter on those URLs.
		description (str, optional): Task description shown in UI.
	"""
	# LOW-02 fix: Initialize mutable defaults
	urls = urls or []
	ctx = ctx or {}
	vuln_config = self.yaml_configuration.get(VULNERABILITY_SCAN) or {}
	should_fetch_gpt_report = vuln_config.get(FETCH_GPT_REPORT, DEFAULT_GET_GPT_REPORT)
	custom_headers = self.yaml_configuration.get(CUSTOM_HEADERS, [])
	'''
	# TODO: Remove custom_header in next major release
		support for custom_header will be remove in next major release, 
		as of now it will be supported for backward compatibility
		only custom_headers will be supported
	'''
	custom_header = self.yaml_configuration.get(CUSTOM_HEADER)
	if custom_header:
		custom_headers.append(custom_header)
	user_agent = vuln_config.get(USER_AGENT) or self.yaml_configuration.get(USER_AGENT)
	threads = vuln_config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
	input_path = f'{self.results_dir}/input_endpoints_crlf.txt'
	output_path = f'{self.results_dir}/{self.filename}'

	if urls:
		with open(input_path, 'w') as f:
			f.write('\n'.join(urls))
	else:
		get_http_urls(
			is_alive=False,
			ignore_files=True,
			write_filepath=input_path,
			ctx=ctx
		)

	notif = Notification.objects.first()
	send_status = notif.send_scan_status_notif if notif else False

	# command builder
	cmd = 'crlfuzz -s'
	cmd += f' -l {input_path}'
	formatted_headers = ' '.join(f'-H "{header}"' for header in custom_headers)
	if formatted_headers:
		cmd += formatted_headers
	cmd += f' -o {output_path}'

	run_command(
		cmd,
		shell=False,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id
	)

	if not os.path.isfile(output_path):
		logger.info('No Results from CRLFuzz')
		return

	crlfs = []
	results = []
	with open(output_path, 'r') as file:
		crlfs = file.readlines()

	for crlf in crlfs:
		url = crlf.strip()

		vuln_data = parse_crlfuzz_result(url)

		http_url = sanitize_url(url)
		subdomain_name = get_subdomain_from_url(http_url)

		subdomain, _ = Subdomain.objects.get_or_create(
			name=subdomain_name,
			scan_history=self.scan,
			target_domain=self.domain
		)

		endpoint, _ = save_endpoint(
			http_url,
			crawl=True,
			subdomain=subdomain,
			ctx=ctx
		)
		if endpoint:
			http_url = endpoint.http_url
			endpoint.save()

		vuln, _ = save_vulnerability(
			target_domain=self.domain,
			http_url=http_url,
			scan_history=self.scan,
			subscan=self.subscan,
			**vuln_data
		)

		if not vuln:
			continue

	# after vulnerability scan is done, we need to run LLM report if
	# should_fetch_gpt_report and either OpenAI key exists or Ollama is enabled
	ollama_settings = OllamaSettings.objects.first()
	use_ollama = ollama_settings and ollama_settings.use_ollama

	if should_fetch_gpt_report and (OpenAiAPIKey.objects.all().first() or use_ollama):
		logger.info('Getting CRLFuzz Vulnerability LLM Report')
		vulns = Vulnerability.objects.filter(
			scan_history__id=self.scan_id
		).filter(
			source=CRLFUZZ
		).exclude(
			severity=0
		)

		_vulns = []
		for vuln in vulns:
			_vulns.append((vuln.name, vuln.http_url))

		_llm_workers = 1 if use_ollama else min(DEFAULT_THREADS, 5)
		with concurrent.futures.ThreadPoolExecutor(max_workers=_llm_workers) as executor:
			future_to_gpt = {executor.submit(get_vulnerability_gpt_report, vuln): vuln for vuln in _vulns}

			# Wait for all tasks to complete
			for future in concurrent.futures.as_completed(future_to_gpt):
				gpt = future_to_gpt[future]
				try:
					future.result()
				except Exception as e:
					logger.error(f"Exception for Vulnerability {vuln}: {e}")

	return results


@app.task(name='s3scanner', queue='main_scan_queue', base=ParaKangTask, bind=True)
def s3scanner(self, ctx=None, description=None):
	if ctx is None:
		ctx = {}
	"""Bucket Scanner

	Args:
		ctx (dict): Context
		description (str, optional): Task description shown in UI.
	"""
	input_path = f'{self.results_dir}/#{self.scan_id}_subdomain_discovery.txt'
	vuln_config = self.yaml_configuration.get(VULNERABILITY_SCAN) or {}
	s3_config = vuln_config.get(S3SCANNER) or {}
	threads = s3_config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
	providers = s3_config.get(PROVIDERS, S3SCANNER_DEFAULT_PROVIDERS)
	scan_history = ScanHistory.objects.filter(pk=self.scan_id).first()
	for provider in providers:
		cmd = f's3scanner -bucket-file {input_path} -enumerate -provider {provider} -threads {threads} -json'
		for line in stream_command(
				cmd,
				history_file=self.history_file,
				scan_id=self.scan_id,
				activity_id=self.activity_id):

			if not isinstance(line, dict):
				continue

			if line.get('bucket', {}).get('exists', 0) == 1:
				result = parse_s3scanner_result(line)
				s3bucket, created = S3Bucket.objects.get_or_create(**result)
				scan_history.buckets.add(s3bucket)
				logger.info(f"s3 bucket added {result['provider']}-{result['name']}-{result['region']}")


@app.task(name='http_crawl', queue='main_scan_queue', base=ParaKangTask, bind=True)
def http_crawl(
		self,
		urls=None,
		method=None,
		recrawl=False,
		ctx=None,
		track=True,
		description=None,
		is_ran_from_subdomain_scan=False,
		should_remove_duplicate_endpoints=True,
		duplicate_removal_fields=None):
	"""Use httpx to query HTTP URLs for important info like page titles, http
	status, etc...

	Args:
		urls (list, optional): A set of URLs to check. Overrides default
			behavior which queries all endpoints related to this scan.
		method (str): HTTP method to use (GET, HEAD, POST, PUT, DELETE).
		recrawl (bool, optional): If False, filter out URLs that have already
			been crawled.
		should_remove_duplicate_endpoints (bool): Whether to remove duplicate endpoints
		duplicate_removal_fields (list): List of Endpoint model fields to check for duplicates

	Returns:
		list: httpx results.
	"""
	# LOW-02 fix: Initialize mutable defaults
	urls = urls or []
	ctx = ctx or {}
	duplicate_removal_fields = duplicate_removal_fields or []
	logger.info('Initiating HTTP Crawl')
	if is_ran_from_subdomain_scan:
		logger.info('Running From Subdomain Scan...')
	cmd = '/go/bin/httpx'
	cfg = self.yaml_configuration.get(HTTP_CRAWL) or {}
	custom_headers = self.yaml_configuration.get(CUSTOM_HEADERS, [])
	'''
	# TODO: Remove custom_header in next major release
		support for custom_header will be remove in next major release, 
		as of now it will be supported for backward compatibility
		only custom_headers will be supported
	'''
	custom_header = self.yaml_configuration.get(CUSTOM_HEADER)
	if custom_header:
		custom_headers.append(custom_header)
	threads = cfg.get(THREADS, DEFAULT_THREADS)
	follow_redirect = cfg.get(FOLLOW_REDIRECT, True)
	self.output_path = None
	input_path = f'{self.results_dir}/httpx_input.txt'
	history_file = f'{self.results_dir}/commands.txt'
	if urls: # direct passing URLs to check
		if self.starting_point_path:
			urls = [u for u in urls if self.starting_point_path in u]

		with open(input_path, 'w') as f:
			f.write('\n'.join(urls))
	else:
		urls = get_http_urls(
			is_uncrawled=not recrawl,
			write_filepath=input_path,
			ctx=ctx
		)
		# logger.debug(urls)

	# exclude urls by pattern
	if self.excluded_paths:
		urls = exclude_urls_by_patterns(self.excluded_paths, urls)

	# If no URLs found, skip it
	if not urls:
		return

	# Re-adjust thread number if few URLs to avoid spinning up a monster to
	# kill a fly.
	if len(urls) < threads:
		threads = len(urls)

	# Do NOT use proxy for http_crawl — httpx probes target's actual HTTP
	# response (content_length, page_title, status_code). Using a proxy here
	# causes free proxies to return error pages → mass deduplication → fewer
	# endpoints for vulnerability scanning. Proxy is only for passive tools.

	# Run command
	cmd += f' -cl -ct -rt -location -td -websocket -cname -asn -cdn -probe -random-agent'
	cmd += f' -t {threads}' if threads > 0 else ''
	formatted_headers = ' '.join(f'-H "{header}"' for header in custom_headers)
	if formatted_headers:
		cmd += formatted_headers
	cmd += f' -json'
	cmd += f' -u {urls[0]}' if len(urls) == 1 else f' -l {input_path}'
	cmd += f' -x {method}' if method else ''
	cmd += f' -silent'
	if follow_redirect:
		cmd += ' -fr'
	results = []
	endpoint_ids = []
	for line in stream_command(
			cmd,
			history_file=history_file,
			scan_id=self.scan_id,
			activity_id=self.activity_id):

		if not line or not isinstance(line, dict):
			continue

		logger.debug(line)

		# No response from endpoint
		if line.get('failed', False):
			continue

		# Parse httpx output
		host = line.get('host', '')
		content_length = line.get('content_length', 0)
		http_status = line.get('status_code')
		http_url, is_redirect = extract_httpx_url(line)
		page_title = line.get('title')
		webserver = line.get('webserver')
		cdn = line.get('cdn', False)
		rt = line.get('time')
		techs = line.get('tech', [])
		cname = line.get('cname', '')
		content_type = line.get('content_type', '')
		response_time = -1
		if rt:
			response_time = float(''.join(ch for ch in rt if not ch.isalpha()))
			if rt[-2:] == 'ms':
				response_time = response_time / 1000

		# Create Subdomain object in DB
		subdomain_name = get_subdomain_from_url(http_url)
		subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)

		if not subdomain:
			continue

		# Save default HTTP URL to endpoint object in DB
		endpoint, created = save_endpoint(
			http_url,
			crawl=False,
			ctx=ctx,
			subdomain=subdomain,
			is_default=is_ran_from_subdomain_scan
		)
		if not endpoint:
			continue
		endpoint.http_status = http_status
		endpoint.page_title = page_title
		endpoint.content_length = content_length
		endpoint.webserver = webserver
		endpoint.response_time = response_time
		endpoint.content_type = content_type
		endpoint.save()
		endpoint_str = f'{http_url} [{http_status}] `{content_length}B` `{webserver}` `{rt}`'
		logger.warning(endpoint_str)
		if endpoint and endpoint.is_alive and endpoint.http_status != 403:
			self.notify(
				fields={'Alive endpoint': f'• {endpoint_str}'},
				add_meta_info=False)

		# Add endpoint to results
		line['_cmd'] = cmd
		line['final_url'] = http_url
		line['endpoint_id'] = endpoint.id
		line['endpoint_created'] = created
		line['is_redirect'] = is_redirect
		results.append(line)

		# Add technology objects to DB
		for technology in techs:
			tech, _ = Technology.objects.get_or_create(name=technology)
			endpoint.techs.add(tech)
			if is_ran_from_subdomain_scan:
				subdomain.technologies.add(tech)
				subdomain.save()
			endpoint.save()
		techs_str = ', '.join([f'`{tech}`' for tech in techs])
		self.notify(
			fields={'Technologies': techs_str},
			add_meta_info=False)

		# Add IP objects for 'a' records to DB
		a_records = line.get('a', [])
		valid_ips = []
		for ip_address in a_records:
			ip, created = save_ip_address(
				ip_address,
				subdomain,
				subscan=self.subscan,
				cdn=cdn)
			if ip:
				valid_ips.append(ip_address)
		if valid_ips:
			ips_str = '• ' + '\n• '.join([f'`{ip}`' for ip in valid_ips])
			self.notify(
				fields={'IPs': ips_str},
				add_meta_info=False)

		# Add IP object for host in DB
		if host:
			ip, created = save_ip_address(
				host,
				subdomain,
				subscan=self.subscan,
				cdn=cdn)
			if ip:
				self.notify(
					fields={'IPs': f'• `{ip.address}`'},
					add_meta_info=False)

		# Save subdomain and endpoint
		if is_ran_from_subdomain_scan:
			# save subdomain stuffs
			subdomain.http_url = http_url
			subdomain.http_status = http_status
			subdomain.page_title = page_title
			subdomain.content_length = content_length
			subdomain.webserver = webserver
			subdomain.response_time = response_time
			subdomain.content_type = content_type
			subdomain.cname = ','.join(cname)
			subdomain.is_cdn = cdn
			if cdn:
				subdomain.cdn_name = line.get('cdn_name')
			subdomain.save()
		endpoint.save()
		endpoint_ids.append(endpoint.id)

	if should_remove_duplicate_endpoints:
		# Remove 'fake' alive endpoints that are just redirects to the same page
		remove_duplicate_endpoints(
			self.scan_id,
			self.domain_id,
			self.subdomain_id,
			filter_ids=endpoint_ids
		)

	# Remove input file
	run_command(
		f'rm {input_path}',
		shell=True,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id)

	return results


#---------------------#
# Notifications tasks #
#---------------------#

@app.task(name='fetch_free_proxies', bind=False, queue='main_scan_queue')
def fetch_free_proxies(country_filter=None):
	"""Fetch fresh proxies from multiple public sources, prune dead entries from
	the existing DB list, then save only live proxies.

	This task is scheduled to run automatically every week (Monday 03:00 UTC)
	via Celery Beat DatabaseScheduler. It can also be triggered manually.

	Behaviour:
	  1. Scrape fresh proxies from 4 public sources.
	  2. Concurrently test every existing proxy — remove dead ones.
	  3. Merge surviving + new proxies, save to DB.
	  4. If no source yields proxies AND nothing alive in DB, the DB is left
	     unchanged so tools can still fall back to 'no proxy' mode.

	Sources:
	  1. proxifly   — JSON CDN (reliable, no scraping)
	  2. proxyscrape — plain-text API (reliable, no scraping)
	  3. free-proxy-list.net — HTML table
	  4. proxylistfree.com   — HTML table

	Args:
		country_filter (str|None): 2-letter ISO country code to filter proxies
		    (e.g. 'ID' for Indonesia). None = all countries.

	Returns:
		dict: {'added': int, 'pruned': int, 'total': int}
	"""
	import re as _re
	import requests as _requests
	from bs4 import BeautifulSoup

	headers = {
		'User-Agent': (
			'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
			'AppleWebKit/537.36 (KHTML, like Gecko) '
			'Chrome/120.0.0.0 Safari/537.36'
		)
	}
	country_filter = (country_filter or '').upper().strip() or None
	collected = set()  # ip:port strings

	def is_valid_proxy(ip, port):
		"""Basic validation: IP format + port range."""
		parts = ip.split('.')
		if len(parts) != 4:
			return False
		try:
			if not all(0 <= int(p) <= 255 for p in parts):
				return False
			port_int = int(port)
			return 1 <= port_int <= 65535
		except (ValueError, TypeError):
			return False

	# ── Source 1: proxifly JSON CDN ─────────────────────────────────────────
	try:
		url = 'https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/http/data.json'
		r = _requests.get(url, headers=headers, timeout=20)
		if r.ok:
			data = r.json()
			for entry in data:
				ip = entry.get('ip', '')
				port = str(entry.get('port', ''))
				country = (entry.get('geolocation') or {}).get('country', '')
				if country_filter and country != country_filter:
					continue
				if is_valid_proxy(ip, port):
					collected.add(f'{ip}:{port}')
			logger.info(f'fetch_free_proxies: proxifly gave {len(collected)} proxies')
	except Exception as e:
		logger.warning(f'fetch_free_proxies: proxifly failed: {e}')

	before_src2 = len(collected)

	# ── Source 2: proxyscrape plain-text API ────────────────────────────────
	try:
		country_param = f'&country={country_filter}' if country_filter else '&country=all'
		url = (
			f'https://api.proxyscrape.com/v3/free-proxy-list/get'
			f'?request=displayproxies&protocol=http&timeout=10000'
			f'{country_param}&ssl=all&anonymity=all&simplified=true'
		)
		r = _requests.get(url, headers=headers, timeout=20)
		if r.ok:
			for line in r.text.strip().splitlines():
				line = line.strip()
				if ':' in line:
					ip, port = line.rsplit(':', 1)
					if is_valid_proxy(ip, port):
						collected.add(f'{ip}:{port}')
		logger.info(f'fetch_free_proxies: proxyscrape added {len(collected) - before_src2}')
	except Exception as e:
		logger.warning(f'fetch_free_proxies: proxyscrape failed: {e}')

	before_src3 = len(collected)

	# ── Source 3: free-proxy-list.net HTML table ─────────────────────────────
	try:
		r = _requests.get('https://free-proxy-list.net/', headers=headers, timeout=20)
		if r.ok:
			soup = BeautifulSoup(r.text, 'lxml')
			table = soup.find('table')
			if table:
				for row in table.find_all('tr')[1:]:
					cols = row.find_all('td')
					if len(cols) < 8:
						continue
					ip = cols[0].text.strip()
					port = cols[1].text.strip()
					country_code = cols[2].text.strip().upper()
					if country_filter and country_code != country_filter:
						continue
					if is_valid_proxy(ip, port):
						collected.add(f'{ip}:{port}')
		logger.info(f'fetch_free_proxies: free-proxy-list added {len(collected) - before_src3}')
	except Exception as e:
		logger.warning(f'fetch_free_proxies: free-proxy-list.net failed: {e}')

	before_src4 = len(collected)

	# ── Source 4: proxylistfree.com HTML table ───────────────────────────────
	try:
		r = _requests.get('https://www.proxylistfree.com/', headers=headers, timeout=20)
		if r.ok:
			soup = BeautifulSoup(r.text, 'lxml')
			table = soup.find('table')
			if table:
				for row in table.find_all('tr')[1:]:
					cols = row.find_all('td')
					# cols: [protocol, ip, port, country, ...]
					if len(cols) < 3:
						continue
					ip = cols[1].text.strip()
					port = cols[2].text.strip()
					# No country code column readily available; skip country filter for this source
					if is_valid_proxy(ip, port):
						collected.add(f'{ip}:{port}')
		logger.info(f'fetch_free_proxies: proxylistfree added {len(collected) - before_src4}')
	except Exception as e:
		logger.warning(f'fetch_free_proxies: proxylistfree.com failed: {e}')

	# ── Merge into DB ────────────────────────────────────────────────────────
	# ── Prune dead proxies from existing DB list ────────────────────────────
	import socket as _socket
	import concurrent.futures as _cf

	from scanEngine.models import Proxy as ProxyModel
	proxy_obj, _ = ProxyModel.objects.get_or_create(pk=1)
	existing_lines = [
		line.strip()
		for line in (proxy_obj.proxies or '').splitlines()
		if line.strip()
	]

	def _tcp_ok(entry):
		"""Return entry if reachable via TCP within 2 seconds, else None."""
		try:
			parts = entry.rsplit(':', 1)
			s = _socket.create_connection((parts[0], int(parts[1])), timeout=2)
			s.close()
			return entry
		except Exception:
			return None

	alive_existing = set()
	if existing_lines:
		logger.info(f'fetch_free_proxies: testing {len(existing_lines)} existing proxies for liveness...')
		with _cf.ThreadPoolExecutor(max_workers=50) as pool:
			for result in pool.map(_tcp_ok, existing_lines):
				if result:
					alive_existing.add(result)
		pruned = len(existing_lines) - len(alive_existing)
		logger.info(f'fetch_free_proxies: pruned {pruned} dead proxies, {len(alive_existing)} still alive')
	else:
		pruned = 0

	if not collected and not alive_existing:
		logger.warning('fetch_free_proxies: no proxies available (sources failed, nothing alive in DB) — keeping DB unchanged')
		return {'added': 0, 'pruned': 0, 'total': len(existing_lines)}

	# ── Merge alive existing + new collected ─────────────────────────────────
	new_entries = collected - alive_existing
	all_proxies = alive_existing | collected
	proxy_obj.proxies = '\n'.join(sorted(all_proxies))
	proxy_obj.save()

	logger.info(
		f'fetch_free_proxies: +{len(new_entries)} new, -{pruned} dead removed, '
		f'{len(all_proxies)} total in DB'
	)
	return {'added': len(new_entries), 'pruned': pruned, 'total': len(all_proxies)}


@app.task(name='send_notif', bind=False, queue='send_notif_queue')
def send_notif(
		message,
		scan_history_id=None,
		subscan_id=None,
		**options):
	if not 'title' in options:
		message = enrich_notification(message, scan_history_id, subscan_id)
	send_discord_message(message, **options)
	send_slack_message(message)
	send_lark_message(message)
	send_telegram_message(message)


@app.task(name='send_scan_notif', bind=False, queue='send_scan_notif_queue')
def send_scan_notif(
		scan_history_id,
		subscan_id=None,
		engine_id=None,
		status='RUNNING'):
	"""Send scan status notification. Works for scan or a subscan if subscan_id
	is passed.

	Args:
		scan_history_id (int, optional): ScanHistory id.
		subscan_id (int, optional): SuScan id.
		engine_id (int, optional): EngineType id.
	"""
	# Get domain, engine, scan_history objects
	engine = EngineType.objects.filter(pk=engine_id).first()
	scan = ScanHistory.objects.filter(pk=scan_history_id).first()
	subscan = SubScan.objects.filter(pk=subscan_id).first()
	tasks = ScanActivity.objects.filter(scan_history=scan) if scan else 0

	# Build notif options
	url = get_scan_url(scan_history_id, subscan_id)
	title = get_scan_title(scan_history_id, subscan_id)
	fields = get_scan_fields(engine, scan, subscan, status, tasks)

	severity = None
	msg = f'{title} {status}\n'
	msg += '\n🡆 '.join(f'**{k}:** {v}' for k, v in fields.items())
	if status:
		severity = STATUS_TO_SEVERITIES.get(status)
	opts = {
		'title': title,
		'url': url,
		'fields': fields,
		'severity': severity
	}
	logger.warning(f'Sending notification "{title}" [{severity}]')

	# inapp notification has to be sent eitherways
	generate_inapp_notification(scan, subscan, status, engine, fields)

	notif = Notification.objects.first()

	if notif and notif.send_scan_status_notif:
		# Send notification
		send_notif(
			msg,
			scan_history_id,
			subscan_id,
			**opts)
	
def generate_inapp_notification(scan, subscan, status, engine, fields):
	scan_type = "Subscan" if subscan else "Scan"
	domain = subscan.subdomain.name if subscan else scan.domain.name
	duration_msg = None
	redirect_link = None
	
	if status == 'RUNNING':
		title = f"{scan_type} Started"
		description = f"{scan_type} has been initiated for {domain}"
		icon = "mdi-play-circle-outline"
		notif_status = 'info'
	elif status == 'SUCCESS':
		title = f"{scan_type} Completed"
		description = f"{scan_type} was successful for {domain}"
		icon = "mdi-check-circle-outline"
		notif_status = 'success'
		duration_msg = f'Completed in {fields.get("Duration")}'
	elif status == 'ABORTED':
		title = f"{scan_type} Aborted"
		description = f"{scan_type} was aborted for {domain}"
		icon = "mdi-alert-circle-outline"
		notif_status = 'warning'
		duration_msg = f'Aborted in {fields.get("Duration")}'
	elif status == 'FAILED':
		title = f"{scan_type} Failed"
		description = f"{scan_type} has failed for {domain}"
		icon = "mdi-close-circle-outline"
		notif_status = 'error'
		duration_msg = f'Failed in {fields.get("Duration")}'

	description += f"<br>Engine: {engine.engine_name if engine else 'N/A'}"
	slug = scan.domain.project.slug if scan else subscan.scan_history.domain.project.slug
	if duration_msg:
		description += f"<br>{duration_msg}"

	if status != 'RUNNING':
		redirect_link = f"/scan/{slug}/detail/{scan.id}" if scan else None

	create_inappnotification(
		title=title,
		description=description,
		notification_type='project',
		project_slug=slug,
		icon=icon,
		is_read=False,
		status=notif_status,
		redirect_link=redirect_link,
		open_in_new_tab=False
	)


@app.task(name='send_task_notif', bind=False, queue='send_task_notif_queue')
def send_task_notif(
		task_name,
		status=None,
		result=None,
		output_path=None,
		traceback=None,
		scan_history_id=None,
		engine_id=None,
		subscan_id=None,
		severity=None,
		add_meta_info=True,
		update_fields={}):
	"""Send task status notification.

	Args:
		task_name (str): Task name.
		status (str, optional): Task status.
		result (str, optional): Task result.
		output_path (str, optional): Task output path.
		traceback (str, optional): Task traceback.
		scan_history_id (int, optional): ScanHistory id.
		subscan_id (int, optional): SuScan id.
		engine_id (int, optional): EngineType id.
		severity (str, optional): Severity (will be mapped to notif colors)
		add_meta_info (bool, optional): Wheter to add scan / subscan info to notif.
		update_fields (dict, optional): Fields key / value to update.
	"""

	# Skip send if notification settings are not configured
	notif = Notification.objects.first()
	if not (notif and notif.send_scan_status_notif):
		return

	# Build fields
	url = None
	fields = {}
	if add_meta_info:
		engine = EngineType.objects.filter(pk=engine_id).first()
		scan = ScanHistory.objects.filter(pk=scan_history_id).first()
		subscan = SubScan.objects.filter(pk=subscan_id).first()
		url = get_scan_url(scan_history_id)
		if status:
			fields['Status'] = f'**{status}**'
		if engine:
			fields['Engine'] = engine.engine_name
		if scan:
			fields['Scan ID'] = f'[#{scan.id}]({url})'
		if subscan:
			url = get_scan_url(scan_history_id, subscan_id)
			fields['Subscan ID'] = f'[#{subscan.id}]({url})'
	title = get_task_title(task_name, scan_history_id, subscan_id)
	if status:
		severity = STATUS_TO_SEVERITIES.get(status)

	msg = f'{title} {status}\n'
	msg += '\n🡆 '.join(f'**{k}:** {v}' for k, v in fields.items())

	# Add fields to update
	for k, v in update_fields.items():
		fields[k] = v

	# Add traceback to notif
	if traceback and notif.send_scan_tracebacks:
		fields['Traceback'] = f'```\n{traceback}\n```'

	# Add files to notif
	files = []
	attach_file = (
		notif.send_scan_output_file and
		output_path and
		result and
		not traceback
	)
	if attach_file:
		output_title = output_path.split('/')[-1]
		files = [(output_path, output_title)]

	# Send notif
	opts = {
		'title': title,
		'url': url,
		'files': files,
		'severity': severity,
		'fields': fields,
		'fields_append': update_fields.keys()
	}
	send_notif(
		msg,
		scan_history_id=scan_history_id,
		subscan_id=subscan_id,
		**opts)


@app.task(name='send_file_to_discord', bind=False, queue='send_file_to_discord_queue')
def send_file_to_discord(file_path, title=None):
	notif = Notification.objects.first()
	do_send = notif and notif.send_to_discord and notif.discord_hook_url
	if not do_send:
		return False

	webhook = DiscordWebhook(
		url=notif.discord_hook_url,
		rate_limit_retry=True,
		username=title or "paraKang Discord Plugin"
	)
	with open(file_path, "rb") as f:
		head, tail = os.path.split(file_path)
		webhook.add_file(file=f.read(), filename=tail)
	webhook.execute()


@app.task(name='send_hackerone_report', bind=False, queue='send_hackerone_report_queue')
def send_hackerone_report(vulnerability_id):
	"""Send HackerOne vulnerability report.

	Args:
		vulnerability_id (int): Vulnerability id.

	Returns:
		int: HTTP response status code.
	"""
	vulnerability = Vulnerability.objects.get(id=vulnerability_id)
	severities = {v: k for k,v in NUCLEI_SEVERITY_MAP.items()}

	# can only send vulnerability report if team_handle exists and send_report is True and api_key exists
	hackerone = Hackerone.objects.filter(send_report=True).first()
	api_key = HackerOneAPIKey.objects.filter(username__isnull=False, key__isnull=False).first()

	if not (vulnerability.target_domain.h1_team_handle and hackerone and api_key):
		logger.error('Missing required data: team handle, Hackerone config, or API key.')
		return {"status_code": 400, "message": "Missing required data"}

	severity_value = severities[vulnerability.severity]
	tpl = hackerone.report_template or ""

	tpl_vars = {
		'{vulnerability_name}': vulnerability.name,
		'{vulnerable_url}': vulnerability.http_url,
		'{vulnerability_severity}': severity_value,
		'{vulnerability_description}': vulnerability.description or '',
		'{vulnerability_extracted_results}': vulnerability.extracted_results or '',
		'{vulnerability_reference}': vulnerability.reference or '',
	}

	# Replace syntax of report template with actual content
	for key, value in tpl_vars.items():
		tpl = tpl.replace(key, value)

	data = {
		"data": {
			"type": "report",
			"attributes": {
				"team_handle": vulnerability.target_domain.h1_team_handle,
				"title": f'{vulnerability.name} found in {vulnerability.http_url}',
				"vulnerability_information": tpl,
				"severity_rating": severity_value,
				"impact": "More information about the impact and vulnerability can be found here: \n" + vulnerability.reference if vulnerability.reference else "NA",
			}
		}
	}

	headers = {
		'Content-Type': 'application/json',
		'Accept': 'application/json'
	}

	r = requests.post(
		'https://api.hackerone.com/v1/hackers/reports',
		auth=(api_key.username, api_key.key),
		json=data,
		headers=headers
	)
	response = r.json()
	status_code = r.status_code
	if status_code == 201:
		vulnerability.hackerone_report_id = response['data']["id"]
		vulnerability.open_status = False
		vulnerability.save()
		return {"status_code": r.status_code, "message": "Report sent successfully"}
	logger.error(f"Error sending report to HackerOne")
	return {"status_code": r.status_code, "message": response}


#-------------#
# Utils tasks #
#-------------#


@app.task(name='parse_nmap_results', bind=False, queue='parse_nmap_results_queue')
def parse_nmap_results(xml_file, output_file=None):
	"""Parse results from nmap output file.

	Args:
		xml_file (str): nmap XML report file path.

	Returns:
		list: List of vulnerabilities found from nmap results.
	"""
	with open(xml_file, encoding='utf8') as f:
		content = f.read()
		try:
			nmap_results = xmltodict.parse(content) # parse XML to dict
		except Exception as e:
			logger.exception(e)
			logger.error(f'Cannot parse {xml_file} to valid JSON. Skipping.')
			return []

	# Write JSON to output file
	if output_file:
		with open(output_file, 'w') as f:
			json.dump(nmap_results, f, indent=4)
	logger.warning(json.dumps(nmap_results, indent=4))
	hosts = (
		nmap_results
		.get('nmaprun', {})
		.get('host', {})
	)
	all_vulns = []
	if isinstance(hosts, dict):
		hosts = [hosts]

	for host in hosts:
		# Grab hostname / IP from output
		hostnames_dict = host.get('hostnames', {})
		if hostnames_dict:
			# Ensure that hostnames['hostname'] is a list for consistency
			hostnames_list = hostnames_dict['hostname'] if isinstance(hostnames_dict['hostname'], list) else [hostnames_dict['hostname']]

			# Extract all the @name values from the list of dictionaries
			hostnames = [entry.get('@name') for entry in hostnames_list]
		else:
			hostnames = [host.get('address')['@addr']]

		# Iterate over each hostname for each port
		for hostname in hostnames:

			# Grab ports from output
			ports = host.get('ports', {}).get('port', [])
			if isinstance(ports, dict):
				ports = [ports]

			for port in ports:
				url_vulns = []
				port_number = port['@portid']
				url = sanitize_url(f'{hostname}:{port_number}')
				logger.info(f'Parsing nmap results for {hostname}:{port_number} ...')
				if not port_number or not port_number.isdigit():
					continue
				port_protocol = port['@protocol']
				scripts = port.get('script', [])
				if isinstance(scripts, dict):
					scripts = [scripts]

				for script in scripts:
					script_id = script['@id']
					script_output = script['@output']
					script_output_table = script.get('table', [])
					logger.debug(f'Ran nmap script "{script_id}" on {port_number}/{port_protocol}:\n{script_output}\n')
					if script_id == 'vulscan':
						vulns = parse_nmap_vulscan_output(script_output)
						url_vulns.extend(vulns)
					elif script_id == 'vulners':
						vulns = parse_nmap_vulners_output(script_output)
						url_vulns.extend(vulns)
					# elif script_id == 'http-server-header':
					# 	TODO: nmap can help find technologies as well using the http-server-header script
					# 	regex = r'(\w+)/([\d.]+)\s?(?:\((\w+)\))?'
					# 	tech_name, tech_version, tech_os = re.match(regex, test_string).groups()
					# 	Technology.objects.get_or_create(...)
					# elif script_id == 'http_csrf':
					# 	vulns = parse_nmap_http_csrf_output(script_output)
					# 	url_vulns.extend(vulns)
					else:
						logger.warning(f'Script output parsing for script "{script_id}" is not supported yet.')

				# Add URL & source to vuln
				for vuln in url_vulns:
					vuln['source'] = NMAP
					# TODO: This should extend to any URL, not just HTTP
					vuln['http_url'] = url
					if 'http_path' in vuln:
						vuln['http_url'] += vuln['http_path']
					all_vulns.append(vuln)

	return all_vulns


def parse_nmap_http_csrf_output(script_output):
	pass


def parse_nmap_vulscan_output(script_output):
	"""Parse nmap vulscan script output.

	Args:
		script_output (str): Vulscan script output.

	Returns:
		list: List of Vulnerability dicts.
	"""
	data = {}
	vulns = []
	provider_name = ''

	# Sort all vulns found by provider so that we can match each provider with
	# a function that pulls from its API to get more info about the
	# vulnerability.
	for line in script_output.splitlines():
		if not line:
			continue
		if not line.startswith('['): # provider line
			if "No findings" in line:
				logger.info(f"No findings: {line}")
				continue
			elif ' - ' in line:
				provider_name, provider_url = tuple(line.split(' - '))
				data[provider_name] = {'url': provider_url.rstrip(':'), 'entries': []}
				continue
			else:
				# Log a warning
				logger.warning(f"Unexpected line format: {line}")
				continue
		reg = r'\[(.*)\] (.*)'
		matches = re.match(reg, line)
		id, title = matches.groups()
		entry = {'id': id, 'title': title}
		data[provider_name]['entries'].append(entry)

	logger.warning('Vulscan parsed output:')
	logger.warning(pprint.pformat(data))

	for provider_name in data:
		if provider_name == 'Exploit-DB':
			logger.error(f'Provider {provider_name} is not supported YET.')
			pass
		elif provider_name == 'IBM X-Force':
			logger.error(f'Provider {provider_name} is not supported YET.')
			pass
		elif provider_name == 'MITRE CVE':
			logger.error(f'Provider {provider_name} is not supported YET.')
			for entry in data[provider_name]['entries']:
				cve_id = entry['id']
				vuln = cve_to_vuln(cve_id)
				vulns.append(vuln)
		elif provider_name == 'OSVDB':
			logger.error(f'Provider {provider_name} is not supported YET.')
			pass
		elif provider_name == 'OpenVAS (Nessus)':
			logger.error(f'Provider {provider_name} is not supported YET.')
			pass
		elif provider_name == 'SecurityFocus':
			logger.error(f'Provider {provider_name} is not supported YET.')
			pass
		elif provider_name == 'VulDB':
			logger.error(f'Provider {provider_name} is not supported YET.')
			pass
		else:
			logger.error(f'Provider {provider_name} is not supported.')
	return vulns


def parse_nmap_vulners_output(script_output, url=''):
	"""Parse nmap vulners script output.

	TODO: Rework this as it's currently matching all CVEs no matter the
	confidence.

	Args:
		script_output (str): Script output.

	Returns:
		list: List of found vulnerabilities.
	"""
	vulns = []
	# Check for CVE in script output
	CVE_REGEX = re.compile(r'.*(CVE-\d\d\d\d-\d+).*')
	matches = CVE_REGEX.findall(script_output)
	matches = list(dict.fromkeys(matches))
	for cve_id in matches: # get CVE info
		vuln = cve_to_vuln(cve_id, vuln_type='nmap-vulners-nse')
		if vuln:
			vulns.append(vuln)
	return vulns


def cve_to_vuln(cve_id, vuln_type=''):
	"""Search for a CVE using CVESearch and return Vulnerability data.

	Args:
		cve_id (str): CVE ID in the form CVE-*

	Returns:
		dict: Vulnerability dict.
	"""
	cve_info = CVESearch('https://cve.circl.lu').id(cve_id)
	if not cve_info:
		logger.error(f'Could not fetch CVE info for cve {cve_id}. Skipping.')
		return None
	vuln_cve_id = cve_info['id']
	vuln_name = vuln_cve_id
	vuln_description = cve_info.get('summary', 'none').replace(vuln_cve_id, '').strip()
	try:
		vuln_cvss = float(cve_info.get('cvss', -1))
	except (ValueError, TypeError):
		vuln_cvss = -1
	vuln_cwe_id = cve_info.get('cwe', '')
	exploit_ids = cve_info.get('refmap', {}).get('exploit-db', [])
	osvdb_ids = cve_info.get('refmap', {}).get('osvdb', [])
	references = cve_info.get('references', [])
	capec_objects = cve_info.get('capec', [])

	# Parse ovals for a better vuln name / type
	ovals = cve_info.get('oval', [])
	if ovals:
		vuln_name = ovals[0]['title']
		vuln_type = ovals[0]['family']

	# Set vulnerability severity based on CVSS score
	vuln_severity = 'info'
	if vuln_cvss < 4:
		vuln_severity = 'low'
	elif vuln_cvss < 7:
		vuln_severity = 'medium'
	elif vuln_cvss < 9:
		vuln_severity = 'high'
	else:
		vuln_severity = 'critical'

	# Build console warning message
	msg = f'{vuln_name} | {vuln_severity.upper()} | {vuln_cve_id} | {vuln_cwe_id} | {vuln_cvss}'
	for id in osvdb_ids:
		msg += f'\n\tOSVDB: {id}'
	for exploit_id in exploit_ids:
		msg += f'\n\tEXPLOITDB: {exploit_id}'
	logger.warning(msg)
	vuln = {
		'name': vuln_name,
		'type': vuln_type,
		'severity': NUCLEI_SEVERITY_MAP[vuln_severity],
		'description': vuln_description,
		'cvss_score': vuln_cvss,
		'references': references,
		'cve_ids': [vuln_cve_id],
		'cwe_ids': [vuln_cwe_id]
	}
	return vuln


def parse_s3scanner_result(line):
	'''
		Parses and returns s3Scanner Data
	'''
	bucket = line['bucket']
	return {
		'name': bucket['name'],
		'region': bucket['region'],
		'provider': bucket['provider'],
		'owner_display_name': bucket['owner_display_name'],
		'owner_id': bucket['owner_id'],
		'perm_auth_users_read': bucket['perm_auth_users_read'],
		'perm_auth_users_write': bucket['perm_auth_users_write'],
		'perm_auth_users_read_acl': bucket['perm_auth_users_read_acl'],
		'perm_auth_users_write_acl': bucket['perm_auth_users_write_acl'],
		'perm_auth_users_full_control': bucket['perm_auth_users_full_control'],
		'perm_all_users_read': bucket['perm_all_users_read'],
		'perm_all_users_write': bucket['perm_all_users_write'],
		'perm_all_users_read_acl': bucket['perm_all_users_read_acl'],
		'perm_all_users_write_acl': bucket['perm_all_users_write_acl'],
		'perm_all_users_full_control': bucket['perm_all_users_full_control'],
		'num_objects': bucket['num_objects'],
		'size': bucket['bucket_size']
	}


def parse_nuclei_result(line):
	"""Parse results from nuclei JSON output.

	Args:
		line (dict): Nuclei JSON line output.

	Returns:
		dict: Vulnerability data.
	"""
	return {
		'name': line['info'].get('name', ''),
		'type': line['type'],
		'severity': NUCLEI_SEVERITY_MAP[line['info'].get('severity', 'unknown')],
		'template': line['template'],
		'template_url': line.get('template-url', []),
		'template_id': line['template-id'],
		'description': line['info'].get('description', ''),
		'matcher_name': line.get('matcher-name', ''),
		'curl_command': line.get('curl-command'),
		'request': line.get('request'),
		'response': line.get('response'),
		'extracted_results': line.get('extracted-results', []),
		'cvss_metrics': line['info'].get('classification', {}).get('cvss-metrics', ''),
		'cvss_score': line['info'].get('classification', {}).get('cvss-score'),
		'cve_ids': line['info'].get('classification', {}).get('cve_id', []) or [],
		'cwe_ids': line['info'].get('classification', {}).get('cwe_id', []) or [],
		'references': line['info'].get('reference', []) or [],
		'tags': line['info'].get('tags', []),
		'source': NUCLEI,
	}


def parse_dalfox_result(line):
	"""Parse results from nuclei JSON output.

	Args:
		line (dict): Nuclei JSON line output.

	Returns:
		dict: Vulnerability data.
	"""

	description = ''
	description += f" Evidence: {line.get('evidence')} <br>" if line.get('evidence') else ''
	description += f" Message: {line.get('message')} <br>" if line.get('message') else ''
	description += f" Payload: {line.get('message_str')} <br>" if line.get('message_str') else ''
	description += f" Vulnerable Parameter: {line.get('param')} <br>" if line.get('param') else ''

	return {
		'name': 'XSS (Cross Site Scripting)',
		'type': 'XSS',
		'severity': DALFOX_SEVERITY_MAP[line.get('severity', 'unknown')],
		'description': description,
		'source': DALFOX,
		'cwe_ids': [line.get('cwe')]
	}


def parse_crlfuzz_result(url):
	"""Parse CRLF results

	Args:
		url (str): CRLF Vulnerable URL

	Returns:
		dict: Vulnerability data.
	"""

	return {
		'name': 'CRLF (HTTP Response Splitting)',
		'type': 'CRLF',
		'severity': 2,
		'description': 'A CRLF (HTTP Response Splitting) vulnerability has been discovered.',
		'source': CRLFUZZ,
	}


def record_exists(model, data, exclude_keys=None):
	if exclude_keys is None:
		exclude_keys = []
	"""
	Check if a record already exists in the database based on the given data.

	Args:
		model (django.db.models.Model): The Django model to check against.
		data (dict): Data dictionary containing fields and values.
		exclude_keys (list): List of keys to exclude from the lookup.

	Returns:
		bool: True if the record exists, False otherwise.
	"""

	# Extract the keys that will be used for the lookup
	lookup_fields = {key: data[key] for key in data if key not in exclude_keys}

	# Return True if a record exists based on the lookup fields, False otherwise
	return model.objects.filter(**lookup_fields).exists()

@app.task(name='geo_localize', bind=False, queue='geo_localize_queue')
def geo_localize(host, ip_id=None):
	"""Uses geoiplookup to find location associated with host.

	Args:
		host (str): Hostname.
		ip_id (int): IpAddress object id.

	Returns:
		startScan.models.CountryISO: CountryISO object from DB or None.
	"""
	if validators.ipv6(host):
		logger.info(f'Ipv6 "{host}" is not supported by geoiplookup. Skipping.')
		return None
	# HIGH-04 fix: Sanitize host to prevent command injection from malicious DNS records
	cmd = f'geoiplookup {sanitize_shell_arg(host)}'
	_, out = run_command(cmd)
	if 'IP Address not found' not in out and "can't resolve hostname" not in out:
		country_iso = out.split(':')[1].strip().split(',')[0]
		country_name = out.split(':')[1].strip().split(',')[1].strip()
		geo_object, _ = CountryISO.objects.get_or_create(
			iso=country_iso,
			name=country_name
		)
		geo_json = {
			'iso': country_iso,
			'name': country_name
		}
		if ip_id:
			ip = IpAddress.objects.get(pk=ip_id)
			ip.geo_iso = geo_object
			ip.save()
		return geo_json
	logger.info(f'Geo IP lookup failed for host "{host}"')
	return None


@app.task(name='query_whois', bind=False, queue='query_whois_queue')
def query_whois(target, force_reload_whois=False):
	"""Query WHOIS information for an IP or a domain name.

	Args:
		target (str): IP address or domain name.
		save_domain (bool): Whether to save domain or not, default False
	Returns:
		dict: WHOIS information.
	"""
	try:
		# TODO: Implement cache whois only for 48 hours otherwise get from whois server
		# TODO: in 3.0
		if not force_reload_whois:
			logger.info(f'Querying WHOIS information for {target} from db...')
			domain_info = get_domain_info_from_db(target)
			if domain_info:
				return format_whois_response(domain_info)
			
		# Query WHOIS information as not found in db
		logger.info(f'Whois info not found in db')
		logger.info(f'Querying WHOIS information for {target} from WHOIS server...')

		domain_info = DottedDict()
		domain_info.target = target

		whois_data = None
		related_domains = []

		with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
			futures_func = {
				executor.submit(get_domain_historical_ip_address, target): 'historical_ips',
				executor.submit(fetch_related_tlds_and_domains, target): 'related_tlds_and_domains',
				executor.submit(reverse_whois, target): 'reverse_whois',
				executor.submit(fetch_whois_data_using_netlas, target): 'whois_data',
			}

			for future in concurrent.futures.as_completed(futures_func):
				func_name = futures_func[future]
				try:
					result = future.result()
					if func_name == 'historical_ips':
						domain_info.historical_ips = result
					elif func_name == 'related_tlds_and_domains':
						domain_info.related_tlds, tlsx_related_domain = result
					elif func_name == 'reverse_whois':
						related_domains = result
					elif func_name == 'whois_data':
						whois_data = result

					logger.debug('*'*100)
					logger.info(f'Task {func_name} finished for target {target}')
					logger.debug(result)
					logger.debug('*'*100)

				except Exception as e:
					logger.error(f'An error occurred while fetching {func_name} for {target}: {str(e)}')
					continue

		logger.info(f'All concurrent whosi lookup tasks finished for target {target}')

		if 'tlsx_related_domain' in locals():
			related_domains += tlsx_related_domain
		
		whois_data = whois_data.get('data', {})

		# related domains can also be fetched from whois_data
		whois_related_domains = whois_data.get('related_domains', [])
		related_domains += whois_related_domains

		# remove duplicate ones
		related_domains = list(set(related_domains))
		domain_info.related_domains = related_domains


		parse_whois_data(domain_info, whois_data)
		saved_domain_info = save_domain_info_to_db(target, domain_info)
		return format_whois_response(domain_info)
	except Exception as e:
		logger.error(f'An error occurred while querying WHOIS information for {target}: {str(e)}')
		return {
			'status': False, 
			'target': target, 
			'result': f'An error occurred while querying WHOIS information for {target}: {str(e)}'
		}


def fetch_related_tlds_and_domains(domain):
	"""
	Fetch related TLDs and domains using TLSx.
	related domains are those that are not part of related TLDs.
	
	Args:
		domain (str): The domain to find related TLDs and domains for.
	
	Returns:
		tuple: A tuple containing two lists (related_tlds, related_domains).
	"""
	logger.info(f"Fetching related TLDs and domains for {domain}")
	related_tlds = set()
	related_domains = set()

	# HIGH-05 fix: Validate domain before shell interpolation
	if not validate_domain(domain):
		logger.warning(f'fetch_related_tlds_and_domains: Invalid domain rejected: {repr(domain[:100])}')
		return [], []

	# Extract the base domain
	extracted = tldextract.extract(domain)
	base_domain = f"{extracted.domain}.{extracted.suffix}"

	# HIGH-05 fix: Sanitize domain and remove shell=True
	cmd = f'tlsx -san -cn -silent -ro -host {sanitize_shell_arg(domain)}'
	_, result = run_command(cmd)

	for line in result.splitlines():
		try:
				line = line.strip()
				if line == "":
					continue
				extracted_result = tldextract.extract(line)
				full_domain = f"{extracted_result.domain}.{extracted_result.suffix}"
				
				if extracted_result.domain == extracted.domain:
					if full_domain != base_domain:
						related_tlds.add(full_domain)
				elif extracted_result.domain != extracted.domain or extracted_result.subdomain:
					related_domains.add(line)
		except Exception as e:
			logger.error(f"An error occurred while fetching related TLDs and domains for {domain}: {str(e)}")
			continue
	
	logger.info(f"Found {len(related_tlds)} related TLDs and {len(related_domains)} related domains for {domain}")
	return list(related_tlds), list(related_domains)



def fetch_whois_data_using_netlas(target):
	"""
		Fetch WHOIS data using netlas.
		Args:
			target (str): IP address or domain name.
		Returns:
			dict: WHOIS information.
	"""
	logger.info(f'Fetching WHOIS data for {target} using Netlas...')
	command = f'netlas host {sanitize_shell_arg(target)} -f json'
	netlas_key = get_netlas_key()
	# MED-04 fix: Pass API key via environment variable to avoid exposure in logs/DB
	command_env = None
	if netlas_key:
		command_env = {**os.environ, 'NETLAS_API_KEY': netlas_key}

	try:
		_, result = run_command(command, remove_ansi_sequence=True, env=command_env)
		
		# catch errors
		if 'Failed to parse response data' in result:
			return {
				'status': False, 
				'message': 'Netlas limit exceeded.'
			}
		
		if 'api key doesn\'t exist' in result:
			return {
				'status': False, 
				'message': 'Invalid Netlas API Key!'
			}
		
		if 'Request limit' in result:
			return {
				'status': False, 
				'message': 'Netlas request limit exceeded.'
			}
		
		data = json.loads(result)

		if not data:
			return {
				'status': False, 
				'message': 'No data available for the given domain or IP.'
			}
		# if 'whois' not in data:
		# 	return {
		# 		'status': False, 
		# 		'message': 'Invalid domain or no WHOIS data available.'
		# 	}

		return {
			'status': True, 
			'data': data
		}

	except json.JSONDecodeError:
		return {
			'status': False, 
			'message': 'Failed to parse JSON response from Netlas.'
		}
	except Exception as e:
		return {
			'status': False, 
			'message': f'An error occurred while fetching WHOIS data: {str(e)}'
		}
	

@app.task(name='remove_duplicate_endpoints', bind=False, queue='remove_duplicate_endpoints_queue')
def remove_duplicate_endpoints(
		scan_history_id,
		domain_id,
		subdomain_id=None,
		filter_ids=[],
		filter_status=[200, 301, 404],
		duplicate_removal_fields=ENDPOINT_SCAN_DEFAULT_DUPLICATE_FIELDS
	):
	"""Remove duplicate endpoints.

	Check for implicit redirections by comparing endpoints:
	- [x] `content_length` similarities indicating redirections
	- [x] `page_title` (check for same page title)
	- [ ] Sign-in / login page (check for endpoints with the same words)

	Args:
		scan_history_id: ScanHistory id.
		domain_id (int): Domain id.
		subdomain_id (int, optional): Subdomain id.
		filter_ids (list): List of endpoint ids to filter on.
		filter_status (list): List of HTTP status codes to filter on.
		duplicate_removal_fields (list): List of Endpoint model fields to check for duplicates
	"""
	logger.info(f'Removing duplicate endpoints based on {duplicate_removal_fields}')
	endpoints = (
		EndPoint.objects
		.filter(scan_history__id=scan_history_id)
		.filter(target_domain__id=domain_id)
	)
	if filter_status:
		endpoints = endpoints.filter(http_status__in=filter_status)

	if subdomain_id:
		endpoints = endpoints.filter(subdomain__id=subdomain_id)

	if filter_ids:
		endpoints = endpoints.filter(id__in=filter_ids)

	for field_name in duplicate_removal_fields:
		cl_query = (
			endpoints
			.values_list(field_name)
			.annotate(mc=Count(field_name))
			.order_by('-mc')
		)
		for (field_value, count) in cl_query:
			if count > DELETE_DUPLICATES_THRESHOLD:
				eps_to_delete = (
					endpoints
					.filter(**{field_name: field_value})
					.order_by('discovered_date')
					.all()[1:]
				)
				msg = f'Deleting {len(eps_to_delete)} endpoints [reason: same {field_name} {field_value}]'
				for ep in eps_to_delete:
					url = urlparse(ep.http_url)
					if url.path in ['', '/', '/login']: # try do not delete the original page that other pages redirect to
						continue
					msg += f'\n\t {ep.http_url} [{ep.http_status}] [{field_name}={field_value}]'
					ep.delete()
				logger.warning(msg)

@app.task(name='run_command', bind=False, queue='run_command_queue')
def run_command(
		cmd, 
		cwd=None, 
		shell=False, 
		history_file=None, 
		scan_id=None, 
		activity_id=None,
		remove_ansi_sequence=False,
		env=None
	):
	"""Run a given command using subprocess module.

	Args:
		cmd (str): Command to run.
		cwd (str): Current working directory.
		echo (bool): Log command.
		shell (bool): Run within separate shell if True.
		history_file (str): Write command + output to history file.
		remove_ansi_sequence (bool): Used to remove ANSI escape sequences from output such as color coding
		env (dict): Environment variables for the subprocess. If None, inherits current environment.
	Returns:
		tuple: Tuple with return_code, output.
	"""
	logger.info(cmd)
	logger.warning(activity_id)

	# Create a command record in the database
	command_obj = Command.objects.create(
		command=cmd,
		created_at=timezone.now(),
		scan_history_id=scan_id,
		activity_id=activity_id)

	# Run the command using subprocess
	popen = subprocess.Popen(
		cmd if shell else cmd.split(),
		shell=shell,
		stdout=subprocess.PIPE,
		stderr=subprocess.STDOUT,
		cwd=cwd,
		env=env,
		universal_newlines=True)
	# MED-06 fix: Limit output size to prevent DB bloat and memory exhaustion
	MAX_OUTPUT_SIZE = 1024 * 1024  # 1 MB
	output = ''
	for stdout_line in iter(popen.stdout.readline, ""):
		item = stdout_line.strip()
		if len(output) < MAX_OUTPUT_SIZE:
			output += '\n' + item
		logger.debug(item)
	popen.stdout.close()
	popen.wait()
	return_code = popen.returncode
	command_obj.output = output[:MAX_OUTPUT_SIZE]
	command_obj.return_code = return_code
	command_obj.save()
	if history_file:
		mode = 'a'
		if not os.path.exists(history_file):
			mode = 'w'
		with open(history_file, mode) as f:
			f.write(f'\n{cmd}\n{return_code}\n{output}\n------------------\n')
	if remove_ansi_sequence:
		output = remove_ansi_escape_sequences(output)
	return return_code, output


#-------------#
# Other utils #
#-------------#

def stream_command(cmd, cwd=None, shell=False, history_file=None, encoding='utf-8', scan_id=None, activity_id=None, trunc_char=None):
	# Log cmd
	logger.info(cmd)
	# logger.warning(activity_id)

	# Create a command record in the database
	command_obj = Command.objects.create(
		command=cmd,
		created_at=timezone.now(),
		scan_history_id=scan_id,
		activity_id=activity_id)

	# Sanitize the cmd
	command = cmd if shell else cmd.split()

	# Run the command using subprocess
	process = subprocess.Popen(
		command,
		stdout=subprocess.PIPE,
		stderr=subprocess.STDOUT,
		universal_newlines=True,
		shell=shell)

	# Log the output in real-time to the database
	output = ""
	# MED-03 fix: Batch DB writes every N lines instead of per-line
	_line_count = 0
	_BATCH_SIZE = 50

	# Process the output
	for line in iter(lambda: process.stdout.readline(), b''):
		if not line:
			break
		line = line.strip()
		ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
		line = ansi_escape.sub('', line)
		line = line.replace('\\x0d\\x0a', '\n')
		if trunc_char and line.endswith(trunc_char):
			line = line[:-1]
		item = line

		# Try to parse the line as JSON
		try:
			item = json.loads(line)
		except json.JSONDecodeError:
			pass

		# Yield the line
		#logger.debug(item)
		yield item

		# Add the log line to the output
		output += line + "\n"
		_line_count += 1

		# MED-03 fix: Only write to DB every _BATCH_SIZE lines
		if _line_count % _BATCH_SIZE == 0:
			command_obj.output = output
			command_obj.save()

	# Retrieve the return code and output
	process.wait()
	return_code = process.returncode

	# Update the return code and final output in the database
	command_obj.output = output
	command_obj.return_code = return_code
	command_obj.save()

	# Append the command, return code and output to the history file
	if history_file is not None:
		with open(history_file, "a") as f:
			f.write(f"{cmd}\n{return_code}\n{output}\n")


def process_httpx_response(line):
	"""TODO: implement this"""


def extract_httpx_url(line):
	"""Extract final URL from httpx results. Always follow redirects to find
	the last URL.

	Args:
		line (dict): URL data output by httpx.

	Returns:
		tuple: (final_url, redirect_bool) tuple.
	"""
	status_code = line.get('status_code', 0)
	final_url = line.get('final_url')
	location = line.get('location')
	chain_status_codes = line.get('chain_status_codes', [])

	# Final URL is already looking nice, if it exists return it
	if final_url:
		return final_url, False
	http_url = line['url'] # fallback to url field

	# Handle redirects manually
	REDIRECT_STATUS_CODES = [301, 302]
	is_redirect = (
		status_code in REDIRECT_STATUS_CODES
		or
		any(x in REDIRECT_STATUS_CODES for x in chain_status_codes)
	)
	if is_redirect and location:
		if location.startswith(('http', 'https')):
			http_url = location
		else:
			http_url = f'{http_url}/{location.lstrip("/")}'

	# Sanitize URL
	http_url = sanitize_url(http_url)

	return http_url, is_redirect


#-------------#
# OSInt utils #
#-------------#

def get_and_save_dork_results(lookup_target, results_dir, type, lookup_keywords=None, lookup_extensions=None, delay=5, page_count=2, scan_history=None):
	"""
		Uses gofuzz to dork and store information

		Args:
			lookup_target (str): target to look into such as stackoverflow or even the target itself
			results_dir (str): Results directory
			type (str): Dork Type Title
			lookup_keywords (str): comma separated keywords or paths to look for
			lookup_extensions (str): comma separated extensions to look for
			delay (int): delay between each requests
			page_count (int): pages in google to extract information
			scan_history (startScan.ScanHistory): Scan History Object

		Returns:
			list | _GOOFUZZ_BLOCKED: list of dork URLs found, or the module-level
			_GOOFUZZ_BLOCKED sentinel if Google blocked this IP.
	"""
	_BLOCK_SIGNAL = 'temporarily blocked your IP'

	_proxy_mode = getattr(scan_history, 'cfg_proxy_mode', 'auto') if scan_history else 'auto'
	_scan_id = scan_history.id if scan_history else None

	# Build a priority list of proxies to try, cycling through up to 5 different
	# ones before giving up.  None sentinel = "run without proxy" (last resort
	# when proxy_mode is 'auto').
	_candidate_proxies = []
	if _proxy_mode != 'none':
		try:
			proxy_obj = Proxy.objects.first()
			if proxy_obj and proxy_obj.use_proxy and proxy_obj.proxies.strip():
				_raw = [p.strip() for p in proxy_obj.proxies.strip().splitlines() if p.strip()]
				random.shuffle(_raw)
				_candidate_proxies = _raw[:5]
		except Exception:
			pass

	# Fallback to no-proxy when in auto mode; or just use [None] if no proxies configured
	if _proxy_mode == 'auto':
		_proxies_to_try = _candidate_proxies + [None]
	elif _candidate_proxies:
		_proxies_to_try = _candidate_proxies
	else:
		_proxies_to_try = [None]

	# Base command (without proxy and output flags — added per-attempt)
	gofuzz_base = f'{GOFUZZ_EXEC_PATH} -t {lookup_target} -d {delay} -p {page_count}'
	if lookup_extensions:
		gofuzz_base += f' -e {lookup_extensions}'
	elif lookup_keywords:
		gofuzz_base += f' -w {lookup_keywords}'

	output_file = f'{results_dir}/gofuzz.txt'
	history_file = f'{results_dir}/commands.txt'

	for _attempt, _proxy in enumerate(_proxies_to_try):
		gofuzz_command = gofuzz_base
		if _proxy:
			gofuzz_proxy = _proxy.split('://', 1)[-1]
			gofuzz_command += f' -r {gofuzz_proxy}'
			if _attempt == 0:
				logger.debug(f'GooFuzz: using proxy {gofuzz_proxy}')
			else:
				logger.info(f'GooFuzz: retry #{_attempt} with proxy {gofuzz_proxy} (previous was blocked)')
		else:
			if _attempt > 0:
				logger.warning(f'GooFuzz: all {_attempt} proxies blocked — falling back to no proxy for {lookup_target}')
			else:
				logger.debug('GooFuzz: no proxy configured — running without proxy (risk of IP block)')

		gofuzz_command += f' -o {output_file}'

		try:
			return_code, output = run_command(
				gofuzz_command,
				shell=False,
				history_file=history_file,
				scan_id=_scan_id,
			)

			# Detect Google IP block via return code 1 or output message
			combined_output = (output or '').lower()
			if return_code == 1 or _BLOCK_SIGNAL.lower() in combined_output:
				remaining = len(_proxies_to_try) - _attempt - 1
				logger.warning(
					f'GooFuzz IP blocked by Google (rc={return_code}, proxy={_proxy or "none"}, '
					f'target={lookup_target}).'
					+ (f' Trying next proxy ({remaining} remaining)...' if remaining else ' All proxies exhausted.')
				)
				continue  # try next proxy in rotation

			# Success — parse results
			results = []
			if not os.path.isfile(output_file):
				return results

			with open(output_file) as f:
				for line in f.readlines():
					url = line.strip()
					if url:
						results.append(url)
						dork, created = Dork.objects.get_or_create(
							type=type,
							url=url
						)
						if scan_history:
							scan_history.dorks.add(dork)

			os.remove(output_file)
			return results

		except Exception as e:
			logger.exception(e)
			return []

	# All proxy options tried — Google is blocking every available IP
	logger.error(
		f'GooFuzz: all {len(_proxies_to_try)} proxy option(s) exhausted for {lookup_target}. '
		'Google has blocked every available IP. Configure more proxies in Settings → Proxy.'
	)
	return _GOOFUZZ_BLOCKED

def save_metadata_info(meta_dict):
	"""Extract metadata from Google Search.

	Args:
		meta_dict (dict): Info dict.

	Returns:
		list: List of startScan.MetaFinderDocument objects.
	"""
	logger.warning(f'Getting metadata for {meta_dict.osint_target}')

	scan_history = ScanHistory.objects.get(id=meta_dict.scan_id)

	# Get metadata
	result = extract_metadata_from_google_search(meta_dict.osint_target, meta_dict.documents_limit)
	if not result:
		logger.error(f'No metadata result from Google Search for {meta_dict.osint_target}.')
		return []

	# Add metadata info to DB
	results = []
	for metadata_name, data in result.get_metadata().items():
		subdomain = Subdomain.objects.get(
			scan_history=meta_dict.scan_id,
			name=meta_dict.osint_target)
		metadata = DottedDict({k: v for k, v in data.items()})
		meta_finder_document = MetaFinderDocument(
			subdomain=subdomain,
			target_domain=meta_dict.domain,
			scan_history=scan_history,
			url=metadata.url,
			doc_name=metadata_name,
			http_status=metadata.status_code,
			producer=metadata.metadata.get('Producer'),
			creator=metadata.metadata.get('Creator'),
			creation_date=metadata.metadata.get('CreationDate'),
			modified_date=metadata.metadata.get('ModDate'),
			author=metadata.metadata.get('Author'),
			title=metadata.metadata.get('Title'),
			os=metadata.metadata.get('OSInfo'))
		meta_finder_document.save()
		results.append(data)
	return results


#-----------------#
# Utils functions #
#-----------------#

def create_scan_activity(scan_history_id, message, status):
	scan_activity = ScanActivity()
	scan_activity.scan_history = ScanHistory.objects.get(pk=scan_history_id)
	scan_activity.title = message
	scan_activity.created_at = timezone.now()
	scan_activity.status = status
	scan_activity.save()
	return scan_activity.id


#--------------------#
# Database functions #
#--------------------#


def save_vulnerability(**vuln_data):
	references = vuln_data.pop('references', None)
	cve_ids = vuln_data.pop('cve_ids', None)
	cwe_ids = vuln_data.pop('cwe_ids', None)
	tags = vuln_data.pop('tags', None)
	subscan = vuln_data.pop('subscan', None)

	# remove nulls
	vuln_data = replace_nulls(vuln_data)

	# Create vulnerability
	vuln, created = Vulnerability.objects.get_or_create(**vuln_data)
	if created:
		vuln.discovered_date = timezone.now()
		vuln.open_status = True

	# MED-02 fix: Batch all M2M additions, then save once at the end
	# Save vuln tags
	for tag_name in tags or []:
		tag, _ = VulnerabilityTags.objects.get_or_create(name=tag_name)
		if tag:
			vuln.tags.add(tag)

	# Save CVEs
	for cve_id in cve_ids or []:
		cve, _ = CveId.objects.get_or_create(name=cve_id)
		if cve:
			vuln.cve_ids.add(cve)

	# Save CWEs
	for cve_id in cwe_ids or []:
		cwe, _ = CweId.objects.get_or_create(name=cve_id)
		if cwe:
			vuln.cwe_ids.add(cwe)

	# Save vuln reference
	for url in references or []:
		ref, _ = VulnerabilityReference.objects.get_or_create(url=url)
		vuln.references.add(ref)

	# Save subscan id in vuln object
	if subscan:
		vuln.vuln_subscan_ids.add(subscan)

	# Single save at the end
	vuln.save()

	return vuln, created


def save_endpoint(
		http_url,
		ctx={},
		crawl=False,
		is_default=False,
		**endpoint_data):
	"""Get or create EndPoint object. If crawl is True, also crawl the endpoint
	HTTP URL with httpx.

	Args:
		http_url (str): Input HTTP URL.
		is_default (bool): If the url is a default url for SubDomains.
		scan_history (startScan.models.ScanHistory): ScanHistory object.
		domain (startScan.models.Domain): Domain object.
		subdomain (starScan.models.Subdomain): Subdomain object.
		results_dir (str, optional): Results directory.
		crawl (bool, optional): Run httpx on endpoint if True. Default: False.
		force (bool, optional): Force crawl even if ENABLE_HTTP_CRAWL mode is on.
		subscan (startScan.models.SubScan, optional): SubScan object.

	Returns:
		tuple: (startScan.models.EndPoint, created) where `created` is a boolean
			indicating if the object is new or already existed.
	"""
	# remove nulls
	endpoint_data = replace_nulls(endpoint_data)

	scheme = urlparse(http_url).scheme
	endpoint = None
	created = False
	if ctx.get('domain_id'):
		domain = Domain.objects.get(id=ctx.get('domain_id'))
		if domain.name not in http_url:
			logger.error(f"{http_url} is not a URL of domain {domain.name}. Skipping.")
			return None, False
	if crawl:
		ctx['track'] = False
		results = http_crawl(
			urls=[http_url],
			method='HEAD',
			ctx=ctx)
		# If proxy was configured but returned no results, retry without proxy.
		# Public proxies often pass TCP checks but fail HTTP tunneling, causing
		# the initial root-domain probe to silently return nothing — which then
		# cascades into 0 endpoints and 0 vulnerability results for the whole scan.
		if not results and ctx.get('proxy_mode', 'auto') != 'none':
			logger.warning(
				f'Initial probe of {http_url} returned no results (proxy may have failed). '
				'Retrying without proxy.'
			)
			fallback_ctx = {**ctx, 'proxy_mode': 'none', 'track': False}
			results = http_crawl(
				urls=[http_url],
				method='HEAD',
				ctx=fallback_ctx)
		if results:
			endpoint_data = results[0]
			endpoint_id = endpoint_data['endpoint_id']
			created = endpoint_data['endpoint_created']
			endpoint = EndPoint.objects.get(pk=endpoint_id)
	elif not scheme:
		return None, False
	else: # add dumb endpoint without probing it
		scan = ScanHistory.objects.filter(pk=ctx.get('scan_history_id')).first()
		domain = Domain.objects.filter(pk=ctx.get('domain_id')).first()
		if not validators.url(http_url):
			return None, False
		http_url = sanitize_url(http_url)

		# Try to get the first matching record (prevent duplicate error)
		endpoints = EndPoint.objects.filter(
			scan_history=scan,
			target_domain=domain,
			http_url=http_url,
			**endpoint_data
		)

		if endpoints.exists():
			endpoint = endpoints.first()
			created = False
		else:
			# No existing record, create a new one
			endpoint = EndPoint.objects.create(
				scan_history=scan,
				target_domain=domain,
				http_url=http_url,
				**endpoint_data
			)
			created = True

	if created:
		endpoint.is_default = is_default
		endpoint.discovered_date = timezone.now()
		endpoint.save()
		subscan_id = ctx.get('subscan_id')
		if subscan_id:
			endpoint.endpoint_subscan_ids.add(subscan_id)
			endpoint.save()

	return endpoint, created


def save_subdomain(subdomain_name, ctx=None):
	if ctx is None:
		ctx = {}
	"""Get or create Subdomain object.

	Args:
		subdomain_name (str): Subdomain name.
		scan_history (startScan.models.ScanHistory): ScanHistory object.

	Returns:
		tuple: (startScan.models.Subdomain, created) where `created` is a
			boolean indicating if the object has been created in DB.
	"""
	scan_id = ctx.get('scan_history_id')
	subscan_id = ctx.get('subscan_id')
	out_of_scope_subdomains = ctx.get('out_of_scope_subdomains', [])
	subdomain_checker = SubdomainScopeChecker(out_of_scope_subdomains)
	valid_domain = (
		validators.domain(subdomain_name) or
		validators.ipv4(subdomain_name) or
		validators.ipv6(subdomain_name)
	)
	if not valid_domain:
		logger.debug(f'{subdomain_name} is not a valid domain. Skipping.')
		return None, False

	if subdomain_checker.is_out_of_scope(subdomain_name):
		logger.error(f'{subdomain_name} is out-of-scope. Skipping.')
		return None, False

	if ctx.get('domain_id'):
		domain = Domain.objects.get(id=ctx.get('domain_id'))
		if domain.name not in subdomain_name:
			logger.error(f"{subdomain_name} is not a subdomain of domain {domain.name}. Skipping.")
			return None, False

	scan = ScanHistory.objects.filter(pk=scan_id).first()
	domain = scan.domain if scan else None
	subdomain, created = Subdomain.objects.get_or_create(
		scan_history=scan,
		target_domain=domain,
		name=subdomain_name)
	if created:
		# logger.warning(f'Found new subdomain {subdomain_name}')
		subdomain.discovered_date = timezone.now()
		if subscan_id:
			subdomain.subdomain_subscan_ids.add(subscan_id)
		subdomain.save()
	return subdomain, created


def save_email(email_address, scan_history=None):
	if not validators.email(email_address):
		logger.info(f'Email {email_address} is invalid. Skipping.')
		return None, False
	email, created = Email.objects.get_or_create(address=email_address)
	# if created:
	# 	logger.warning(f'Found new email address {email_address}')

	# Add email to ScanHistory
	if scan_history:
		scan_history.emails.add(email)
		scan_history.save()

	return email, created


def save_employee(name, designation, scan_history=None):
	employee, created = Employee.objects.get_or_create(
		name=name,
		designation=designation)
	# if created:
	# 	logger.warning(f'Found new employee {name}')

	# Add employee to ScanHistory
	if scan_history:
		scan_history.employees.add(employee)
		scan_history.save()

	return employee, created


def save_ip_address(ip_address, subdomain=None, subscan=None, **kwargs):
	if not (validators.ipv4(ip_address) or validators.ipv6(ip_address)):
		logger.info(f'IP {ip_address} is not a valid IP. Skipping.')
		return None, False
	ip, created = IpAddress.objects.get_or_create(address=ip_address)
	# if created:
	# 	logger.warning(f'Found new IP {ip_address}')

	# Set extra attributes
	for key, value in kwargs.items():
		setattr(ip, key, value)
	ip.save()

	# Add IP to subdomain
	if subdomain:
		subdomain.ip_addresses.add(ip)
		subdomain.save()

	# Add subscan to IP
	if subscan:
		ip.ip_subscan_ids.add(subscan)

	# Geo-localize IP asynchronously
	if created:
		geo_localize.delay(ip_address, ip.id)

	return ip, created


def save_imported_subdomains(subdomains, ctx=None):
	if ctx is None:
		ctx = {}
	"""Take a list of subdomains imported and write them to from_imported.txt.

	Args:
		subdomains (list): List of subdomain names.
		scan_history (startScan.models.ScanHistory): ScanHistory instance.
		domain (startScan.models.Domain): Domain instance.
		results_dir (str): Results directory.
	"""
	domain_id = ctx['domain_id']
	domain = Domain.objects.get(pk=domain_id)
	results_dir = ctx.get('results_dir', PARAKANG_RESULTS)

	# Validate each subdomain and de-duplicate entries
	subdomains = list(set([
		subdomain for subdomain in subdomains
		if validators.domain(subdomain) and domain.name == get_domain_from_subdomain(subdomain)
	]))
	if not subdomains:
		return

	logger.warning(f'Found {len(subdomains)} imported subdomains.')
	with open(f'{results_dir}/from_imported.txt', 'w+') as output_file:
		for name in subdomains:
			subdomain_name = name.strip()
			subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)
			subdomain.is_imported_subdomain = True
			subdomain.save()
			output_file.write(f'{subdomain}\n')


@app.task(name='query_reverse_whois', bind=False, queue='query_reverse_whois_queue')
def query_reverse_whois(lookup_keyword):
	"""Queries Reverse WHOIS information for an organization or email address.

	Args:
		lookup_keyword (str): Registrar Name or email
	Returns:
		dict: Reverse WHOIS information.
	"""

	return reverse_whois(lookup_keyword)


@app.task(name='query_ip_history', bind=False, queue='query_ip_history_queue')
def query_ip_history(domain):
	"""Queries the IP history for a domain

	Args:
		domain (str): domain_name
	Returns:
		list: list of historical ip addresses
	"""

	return get_domain_historical_ip_address(domain)


@app.task(name='llm_vulnerability_description', bind=False, queue='llm_queue')
def llm_vulnerability_description(vulnerability_id):
	"""Generate and store Vulnerability Description using GPT.

	Args:
		vulnerability_id (Vulnerability Model ID): Vulnerability ID to fetch Description.
	"""
	logger.info('Getting GPT Vulnerability Description')
	try:
		lookup_vulnerability = Vulnerability.objects.get(id=vulnerability_id)
		lookup_url = urlparse(lookup_vulnerability.http_url)
		path = lookup_url.path
	except Exception as e:
		return {
			'status': False,
			'error': str(e)
		}

	# check in db GPTVulnerabilityReport model if vulnerability description and path matches
	if not path:
		path = '/'
	stored = GPTVulnerabilityReport.objects.filter(url_path=path).filter(title=lookup_vulnerability.name).first()
	if stored and stored.description and stored.impact and stored.remediation:
		logger.info('Found cached Vulnerability Description')
		response = {
			'status': True,
			'description': stored.description,
			'impact': stored.impact,
			'remediation': stored.remediation,
			'references': [url.url for url in stored.references.all()]
		}
	else:
		logger.info('Fetching new Vulnerability Description')
		vulnerability_description = get_gpt_vuln_input_description(
			lookup_vulnerability.name,
			path
		)
		# one can add more description here later

		gpt_generator = LLMVulnerabilityReportGenerator(logger=logger)
		response = gpt_generator.get_vulnerability_description(vulnerability_description)
		logger.info(response)
		# Only save to DB if we got a valid response with actual content
		if response.get('status') and response.get('description'):
			add_gpt_description_db(
				lookup_vulnerability.name,
				path,
				response.get('description'),
				response.get('impact'),
				response.get('remediation'),
				response.get('references', [])
			)
		else:
			logger.warning(f'LLM failed for {lookup_vulnerability.name}: {response.get("error", "unknown error")}')
			return response

	# for all vulnerabilities with the same vulnerability name this description has to be stored.
	# also the condition is that the url must contain a part of this.

	for vuln in Vulnerability.objects.filter(name=lookup_vulnerability.name, http_url__icontains=path):
		vuln.description = response.get('description', vuln.description)
		vuln.impact = response.get('impact')
		vuln.remediation = response.get('remediation')
		vuln.is_gpt_used = True
		vuln.save()

		for url in response.get('references', []):
			ref, created = VulnerabilityReference.objects.get_or_create(url=url)
			vuln.references.add(ref)
			vuln.save()

	return response
