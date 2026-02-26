"""
Security Utilities Module
==================================
Centralized security functions for input validation, command sanitization,
and safe execution patterns. This module implements defense-in-depth
strategies for preventing command injection, path traversal, XSS, and
other common attack vectors.

Author: Security Audit
Date: 2026-02-25
"""

import configparser
import io
import logging
import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple, Union

import yaml

logger = logging.getLogger(__name__)

# =============================================================================
# Domain & Input Validation
# =============================================================================

# Strict domain name regex per RFC 1035 + RFC 1123
# Allows: alphanumeric, hyphens, dots. No shell metacharacters.
DOMAIN_REGEX = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*'
    r'[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
)

# IP address regex (IPv4)
IPV4_REGEX = re.compile(
    r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$'
)

# URL-safe characters (no shell metacharacters)
SAFE_URL_REGEX = re.compile(
    r'^https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+$'
)

# Shell metacharacters that MUST be blocked
SHELL_DANGEROUS_CHARS = set(';|&`$(){}[]<>!#\\"\'\n\r\t\x00')

# Allowed scan types whitelist for subscan dispatch
ALLOWED_SCAN_TYPES = {
    'subdomain_discovery',
    'osint',
    'port_scan',
    'vulnerability_scan',
    'dir_file_fuzz',
    'fetch_url',
    'dorking',
    'screenshot',
    'waf_detection',
}


def validate_domain(domain: str) -> bool:
    """Validate that a string is a safe domain name.
    
    Blocks any shell metacharacters and validates against RFC 1035/1123.
    
    Args:
        domain: The domain string to validate.
        
    Returns:
        True if the domain is valid and safe, False otherwise.
    """
    if not domain or not isinstance(domain, str):
        return False
    
    # Length check (max 253 chars per RFC 1035)
    if len(domain) > 253:
        return False
    
    # Check for shell metacharacters
    if any(c in SHELL_DANGEROUS_CHARS for c in domain):
        logger.warning(f'Domain contains dangerous characters: {repr(domain[:50])}')
        return False
    
    # Validate against domain regex
    if DOMAIN_REGEX.match(domain):
        return True
    
    # Also allow bare IPv4 addresses
    if IPV4_REGEX.match(domain):
        return True
    
    return False


def sanitize_domain(domain: str) -> str:
    """Sanitize a domain name by removing dangerous characters.
    
    Args:
        domain: The domain to sanitize.
        
    Returns:
        Sanitized domain string.
        
    Raises:
        ValueError: If the domain cannot be sanitized to a valid format.
    """
    if not domain or not isinstance(domain, str):
        raise ValueError('Invalid domain: empty or non-string')
    
    # Strip whitespace
    domain = domain.strip()
    
    # Remove any shell metacharacters
    sanitized = ''.join(c for c in domain if c not in SHELL_DANGEROUS_CHARS)
    
    if not validate_domain(sanitized):
        raise ValueError(f'Domain failed validation after sanitization: {repr(domain[:50])}')
    
    return sanitized


def validate_url(url: str) -> bool:
    """Validate that a URL is safe for use in commands.
    
    Args:
        url: The URL to validate.
        
    Returns:
        True if the URL is valid and safe.
    """
    if not url or not isinstance(url, str):
        return False
    
    if len(url) > 2048:
        return False
    
    # Check for shell metacharacters (except those valid in URLs)
    dangerous_in_url = set(';|&`$(){}[]<>!\n\r\t\x00')
    if any(c in dangerous_in_url for c in url):
        return False
    
    return bool(SAFE_URL_REGEX.match(url))


# =============================================================================
# Safe Command Execution
# =============================================================================


def build_safe_command(tool: str, args: List[str]) -> List[str]:
    """Build a safe command as a list of arguments (no shell interpretation).
    
    This function ensures that all arguments are passed as separate list
    elements, preventing shell injection.
    
    Args:
        tool: The tool/binary name (e.g., 'subfinder', 'naabu').
        args: List of arguments to pass to the tool.
        
    Returns:
        Command as a list of strings, safe for subprocess.run(..., shell=False).
        
    Raises:
        ValueError: If tool name contains dangerous characters.
    """
    # Validate tool name
    if not re.match(r'^[a-zA-Z0-9_\-./]+$', tool):
        raise ValueError(f'Invalid tool name: {repr(tool)}')
    
    cmd = [tool] + [str(arg) for arg in args]
    return cmd


def safe_subprocess_run(
    cmd: List[str],
    cwd: Optional[str] = None,
    timeout: int = 3600,
    capture_output: bool = True,
    env: Optional[dict] = None,
) -> subprocess.CompletedProcess:
    """Execute a command safely without shell interpretation.
    
    Args:
        cmd: Command as a list of strings.
        cwd: Working directory.
        timeout: Timeout in seconds (default: 1 hour).
        capture_output: Whether to capture stdout/stderr.
        env: Environment variables.
        
    Returns:
        subprocess.CompletedProcess result.
    """
    logger.debug(f'Executing command: {cmd}')
    
    return subprocess.run(
        cmd,
        shell=False,  # NEVER use shell=True
        cwd=cwd,
        timeout=timeout,
        capture_output=capture_output,
        text=True,
        env=env,
    )


def sanitize_shell_arg(value: str) -> str:
    """Sanitize a single value for safe use in shell commands.
    
    Uses shlex.quote() to properly escape shell metacharacters.
    This should only be used when shell=True is absolutely necessary
    (e.g., for pipe chains). Prefer build_safe_command() instead.
    
    Args:
        value: The value to sanitize.
        
    Returns:
        Shell-quoted string safe for interpolation.
    """
    if not isinstance(value, str):
        value = str(value)
    return shlex.quote(value)


# =============================================================================
# Path Security
# =============================================================================


def is_safe_path(base_dir: str, target_path: str) -> bool:
    """Check if a target path is safely within the base directory.
    
    Prevents path traversal attacks (e.g., ../../etc/passwd).
    
    Args:
        base_dir: The allowed base directory.
        target_path: The path to validate.
        
    Returns:
        True if target_path is within base_dir.
    """
    try:
        base = Path(base_dir).resolve()
        target = Path(target_path).resolve()
        return str(target).startswith(str(base))
    except (ValueError, OSError):
        return False


def safe_file_write(base_dir: str, filename: str, content: str, 
                    allowed_extensions: Optional[List[str]] = None) -> str:
    """Safely write content to a file within a base directory.
    
    Validates the path to prevent directory traversal and optionally
    checks file extension.
    
    Args:
        base_dir: The allowed base directory.
        filename: The filename (no path components allowed).
        content: Content to write.
        allowed_extensions: Optional list of allowed extensions (e.g., ['.yaml', '.txt']).
        
    Returns:
        The full path of the written file.
        
    Raises:
        ValueError: If the path is unsafe or extension is not allowed.
    """
    # Strip path separators from filename to prevent traversal
    safe_name = os.path.basename(filename)
    if safe_name != filename:
        raise ValueError(f'Filename contains path separators: {repr(filename)}')
    
    # Check extension
    if allowed_extensions:
        _, ext = os.path.splitext(safe_name)
        if ext.lower() not in allowed_extensions:
            raise ValueError(f'File extension {ext} not allowed. Allowed: {allowed_extensions}')
    
    full_path = os.path.join(base_dir, safe_name)
    
    # Verify path is within base_dir
    if not is_safe_path(base_dir, full_path):
        raise ValueError(f'Path traversal detected: {repr(filename)}')
    
    with open(full_path, 'w') as f:
        f.write(content)
    
    return full_path


def safe_delete_scan_results(domain_name: str, results_base_dir: str = '/usr/src/app/scan_results') -> bool:
    """Safely delete scan results for a domain.
    
    Uses glob with validated domain name, never shell commands.
    
    Args:
        domain_name: The domain whose results to delete.
        results_base_dir: Base directory for scan results.
        
    Returns:
        True if deletion was successful.
    """
    import glob as glob_module
    
    if not validate_domain(domain_name):
        logger.error(f'Cannot delete results: invalid domain name {repr(domain_name[:50])}')
        return False
    
    # Construct safe path
    pattern = os.path.join(results_base_dir, f'{domain_name}*')
    
    for path in glob_module.glob(pattern):
        # Double-check each path is within the base directory
        if is_safe_path(results_base_dir, path):
            if os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=True)
            else:
                os.remove(path)
            logger.info(f'Deleted scan results: {path}')
        else:
            logger.warning(f'Skipping unsafe path during cleanup: {path}')
    
    return True


# =============================================================================
# YAML Config Validation
# =============================================================================


def validate_yaml_config(content: str, max_size: int = 65536) -> Tuple[bool, str]:
    """Validate YAML configuration content before writing to disk.
    
    Args:
        content: The YAML content to validate.
        max_size: Maximum allowed content size in bytes.
        
    Returns:
        Tuple of (is_valid, error_message).
    """
    if not content or not isinstance(content, str):
        return False, 'Content is empty or not a string'
    
    if len(content) > max_size:
        return False, f'Content exceeds maximum size of {max_size} bytes'
    
    try:
        parsed = yaml.safe_load(content)
        if parsed is None:
            return False, 'YAML content is empty after parsing'
        if not isinstance(parsed, (dict, list)):
            return False, 'YAML root must be a mapping or sequence'
        return True, ''
    except yaml.YAMLError as e:
        return False, f'Invalid YAML syntax: {str(e)}'


def validate_ini_config(content: str, max_size: int = 65536) -> Tuple[bool, str]:
    """Validate INI configuration content before writing to disk.
    
    Used for tools like Amass that use INI format configuration files.
    
    Args:
        content: The INI content to validate.
        max_size: Maximum allowed content size in bytes.
        
    Returns:
        Tuple of (is_valid, error_message).
    """
    if not content or not isinstance(content, str):
        return False, 'Content is empty or not a string'
    
    if len(content) > max_size:
        return False, f'Content exceeds maximum size of {max_size} bytes'
    
    # Check for potentially dangerous content patterns
    dangerous_patterns = [
        r'[`$]\(',       # Command substitution
        r'\$\{',         # Variable expansion
        r';\s*\w+',      # Command chaining after semicolons
        r'\|\s*\w+',     # Pipe to commands
    ]
    for pattern in dangerous_patterns:
        if re.search(pattern, content):
            return False, f'Content contains potentially dangerous pattern: {pattern}'
    
    try:
        parser = configparser.ConfigParser()
        parser.read_string(content)
        return True, ''
    except configparser.Error as e:
        return False, f'Invalid INI syntax: {str(e)}'


# =============================================================================
# Tool Command Whitelist
# =============================================================================


# Allowed install command patterns
ALLOWED_INSTALL_PREFIXES = [
    'pip3 install',
    'pip install',
    'go install',
    'git clone https://github.com/',
    'git clone https://gitlab.com/',
    'apt-get install',
    'apt install',
    'npm install',
]


def validate_install_command(command: str) -> Tuple[bool, str]:
    """Validate a tool install command against a whitelist of safe patterns.
    
    Args:
        command: The install command to validate.
        
    Returns:
        Tuple of (is_valid, error_message).
    """
    if not command or not isinstance(command, str):
        return False, 'Command is empty'
    
    command = command.strip()
    
    # Check for command chaining operators
    dangerous_operators = ['&&', '||', ';', '|', '`', '$(', '${', '\n', '\r']
    for op in dangerous_operators:
        if op in command:
            return False, f'Command contains dangerous operator: {repr(op)}'
    
    # Check against whitelist
    for prefix in ALLOWED_INSTALL_PREFIXES:
        if command.startswith(prefix):
            return True, ''
    
    return False, f'Command does not match any allowed pattern. Allowed prefixes: {ALLOWED_INSTALL_PREFIXES}'


# =============================================================================
# Scan Type Whitelist for Subscan
# =============================================================================


def get_scan_method(scan_type: str, scan_functions: dict) -> Optional[callable]:
    """Safely resolve a scan type to its function using an explicit whitelist.
    
    Replaces the dangerous globals().get(scan_type) pattern.
    
    Args:
        scan_type: The scan type string (e.g., 'subdomain_discovery').
        scan_functions: Dict mapping scan type names to their callable functions.
        
    Returns:
        The scan function if found and allowed, None otherwise.
    """
    if scan_type not in ALLOWED_SCAN_TYPES:
        logger.warning(f'Scan type {repr(scan_type)} is not in the allowed whitelist')
        return None
    
    method = scan_functions.get(scan_type)
    if method is None:
        logger.warning(f'Scan type {repr(scan_type)} not found in scan_functions dict')
    
    return method
