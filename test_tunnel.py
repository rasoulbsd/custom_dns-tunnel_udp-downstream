#!/usr/bin/env python3
"""
Comprehensive DNS Tunnel Test Suite

Tests all combinations of uplink and response modes:
- UDP uplink + UDP response
- DNS uplink + DNS response  
- Hybrid uplink + Hybrid response
- DNS uplink + UDP response (classic mode)
- UDP uplink + DNS response (reverse mode)

For each mode, tests:
- Small packet (1 byte)
- Medium packet (100 bytes)
- Large packet (1000+ bytes for fragmentation)

Verifies:
- Data integrity (sent == received)
- Correct packet types in logs
"""

import socket
import subprocess
import time
import json
import os
import sys
import signal
import tempfile
import threading
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, List, Tuple

# Configuration - using high ports to avoid conflicts
# Note: CLIENT_PORT is where client listens for local apps AND receives responses
# SERVER_UDP_PORT is where server listens for UDP uplink queries (must be different from CLIENT_PORT)
ECHO_PORT = 18080
CLIENT_PORT = 15355       # Client listens for local apps here AND receives UDP responses
SERVER_DNS_PORT = 15353   # Server listens for DNS queries here
SERVER_UDP_QUERY_PORT = 15356   # Server listens for UDP queries here (for UDP uplink)
TIMEOUT = 5.0
BUILD_TIMEOUT = 120

@dataclass
class TestResult:
    name: str
    success: bool
    sent_data: bytes
    received_data: Optional[bytes]
    latency_ms: float
    error: Optional[str] = None

@dataclass
class ModeTest:
    uplink_mode: str
    response_mode: str
    expected_uplink_log: str
    expected_response_log: str

# Test modes
TEST_MODES = [
    ModeTest("udp", "udp", "[UDP-UPLINK]", "[UDP-RESPONSE]"),
    ModeTest("dns", "dns", "[DNS-UPLINK]", "[DNS-RESPONSE]"),
    ModeTest("hybrid", "hybrid", "[HYBRID-UPLINK]", "[HYBRID-RESPONSE]"),
    ModeTest("dns", "udp", "[DNS-UPLINK]", "[UDP-RESPONSE]"),
    ModeTest("udp", "dns", "[UDP-UPLINK]", "[DNS-RESPONSE]"),
]

# Test payloads
TEST_PAYLOADS = [
    ("small", b"A"),
    ("medium", b"X" * 100),
    ("large", b"L" * 1000),
]


class ProcessManager:
    """Manages subprocesses for testing"""
    
    def __init__(self):
        self.processes: List[subprocess.Popen] = []
        self.log_files: List[str] = []
        
    def start(self, cmd: List[str], name: str, cwd: str = None) -> Tuple[subprocess.Popen, str]:
        """Start a process and capture its output to a log file"""
        log_file = tempfile.mktemp(suffix=f"_{name}.log")
        self.log_files.append(log_file)
        
        # Source cargo env for WSL compatibility
        env = {**os.environ, 'RUST_LOG': 'debug'}
        
        with open(log_file, 'w') as f:
            proc = subprocess.Popen(
                cmd,
                stdout=f,
                stderr=subprocess.STDOUT,
                cwd=cwd,
                env=env,
                shell=False,
            )
        self.processes.append(proc)
        return proc, log_file
    
    def stop_all(self):
        """Stop all managed processes"""
        for proc in self.processes:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except:
                try:
                    proc.kill()
                except:
                    pass
        self.processes.clear()
        
    def cleanup_logs(self):
        """Remove log files"""
        for log_file in self.log_files:
            try:
                os.remove(log_file)
            except:
                pass
        self.log_files.clear()


class EchoServer:
    """Simple UDP echo server"""
    
    def __init__(self, port: int):
        self.port = port
        self.sock = None
        self.running = False
        self.thread = None
        self.received_data: List[bytes] = []
        
    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('127.0.0.1', self.port))
        self.sock.settimeout(0.5)
        self.running = True
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        print(f"Echo server started on port {self.port}")
        
    def _run(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(65535)
                self.received_data.append(data)
                self.sock.sendto(data, addr)
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"Echo server error: {e}")
                    
    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        if self.sock:
            self.sock.close()
            
    def clear(self):
        self.received_data.clear()


def create_config(uplink_mode: str, response_mode: str, is_client: bool, config_dir: str) -> str:
    """Create a config file for client or server
    
    Architecture:
    - Test app -> CLIENT_PORT (client listens for local apps)
    - Client -> SERVER_DNS_PORT (for DNS queries) or SERVER_UDP_QUERY_PORT (for UDP queries)
    - Server -> ECHO_PORT (forward to echo server)
    - Echo -> Server (echo response)
    - Server -> CLIENT_PORT (send response back to client's local_udp port)
    """
    if is_client:
        # Client config:
        # - resolvers: DNS resolvers for DNS uplink mode
        # - server_udp_addr: Server UDP address for UDP uplink mode
        config = {
            "local_udp": f"127.0.0.1:{CLIENT_PORT}",
            "uplink_mode": uplink_mode,
            "response_mode": response_mode,
            "domains": ["tunnel.example.com"],
            "resolvers": [f"127.0.0.1:{SERVER_DNS_PORT}"],  # DNS resolvers
            "server_udp_addr": f"127.0.0.1:{SERVER_UDP_QUERY_PORT}",  # UDP uplink destination
            "max_subdomain_length": 63,
            "min_subdomain_length": 0,
            "rotate_resolvers": False,
            "randomize_local_port": False,
            "plain_mode": False
        }
        filename = "test_client_config.json"
    else:
        config = {
            "dns_bind": f"0.0.0.0:{SERVER_DNS_PORT}",
            "udp_query_port": SERVER_UDP_QUERY_PORT,  # Server listens for UDP queries here
            "target_udp": f"127.0.0.1:{ECHO_PORT}",
            "client_udp_port": CLIENT_PORT,  # Responses go to client's local_udp port
            "response_mode": response_mode,
            "domains": ["tunnel.example.com"],
            "max_subdomain_length": 63,
            "min_subdomain_length": 0,
            "randomize_dns_port": False,
            "plain_mode": False
        }
        filename = "test_server_config.json"
    
    filepath = os.path.join(config_dir, filename)
    with open(filepath, 'w') as f:
        json.dump(config, f, indent=2)
    return filepath


def send_and_receive(data: bytes, timeout: float = TIMEOUT) -> Tuple[Optional[bytes], float]:
    """Send data through the tunnel and receive the echoed response"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    
    try:
        start = time.time()
        sock.sendto(data, ('127.0.0.1', CLIENT_PORT))
        
        try:
            response, _ = sock.recvfrom(65535)
            latency = (time.time() - start) * 1000
            return response, latency
        except socket.timeout:
            return None, 0.0
    finally:
        sock.close()


def check_log_for_pattern(log_file: str, pattern: str) -> bool:
    """Check if a log file contains a specific pattern"""
    try:
        with open(log_file, 'r') as f:
            content = f.read()
            return pattern in content
    except:
        return False


def build_project(project_dir: str) -> bool:
    """Build the Rust project"""
    print("Building project...")
    try:
        result = subprocess.run(
            ["cargo", "build", "--release"],
            cwd=project_dir,
            capture_output=True,
            text=True,
            timeout=BUILD_TIMEOUT
        )
        if result.returncode != 0:
            print(f"Build failed:\n{result.stderr}")
            return False
        print("Build successful")
        return True
    except subprocess.TimeoutExpired:
        print("Build timed out")
        return False
    except Exception as e:
        print(f"Build error: {e}")
        return False


def run_test_mode(mode: ModeTest, project_dir: str, pm: ProcessManager) -> List[TestResult]:
    """Run all payload tests for a specific mode"""
    results = []
    
    print(f"\n{'='*60}")
    print(f"Testing: uplink={mode.uplink_mode}, response={mode.response_mode}")
    print(f"{'='*60}")
    
    # Create config files
    client_config = create_config(mode.uplink_mode, mode.response_mode, True, project_dir)
    server_config = create_config(mode.uplink_mode, mode.response_mode, False, project_dir)
    
    # Start echo server
    echo = EchoServer(ECHO_PORT)
    echo.start()
    time.sleep(0.5)
    
    try:
        # Start server (using pre-built binaries)
        server_binary = os.path.join(project_dir, "target", "release", "server")
        if os.path.exists(server_binary):
            server_cmd = [server_binary, "--config", server_config]
        else:
            server_cmd = ["cargo", "run", "--release", "--bin", "server", "--", "--config", server_config]
        
        server_proc, server_log = pm.start(server_cmd, "server", project_dir)
        time.sleep(3)  # Wait for server to start
        
        # Start client (using pre-built binaries)
        client_binary = os.path.join(project_dir, "target", "release", "client")
        if os.path.exists(client_binary):
            client_cmd = [client_binary, "--config", client_config]
        else:
            client_cmd = ["cargo", "run", "--release", "--bin", "client", "--", "--config", client_config]
        
        client_proc, client_log = pm.start(client_cmd, "client", project_dir)
        time.sleep(3)  # Wait for client to start
        
        # Run tests for each payload
        for payload_name, payload_data in TEST_PAYLOADS:
            test_name = f"{mode.uplink_mode}_{mode.response_mode}_{payload_name}"
            print(f"  Testing {payload_name} payload ({len(payload_data)} bytes)...", end=" ")
            
            echo.clear()
            response, latency = send_and_receive(payload_data)
            
            if response is None:
                print("TIMEOUT")
                results.append(TestResult(
                    name=test_name,
                    success=False,
                    sent_data=payload_data,
                    received_data=None,
                    latency_ms=0,
                    error="Timeout waiting for response"
                ))
            elif response != payload_data:
                print(f"MISMATCH (sent {len(payload_data)}, got {len(response)})")
                results.append(TestResult(
                    name=test_name,
                    success=False,
                    sent_data=payload_data,
                    received_data=response,
                    latency_ms=latency,
                    error=f"Data mismatch: sent {len(payload_data)} bytes, got {len(response)} bytes"
                ))
            else:
                print(f"OK ({latency:.1f}ms)")
                results.append(TestResult(
                    name=test_name,
                    success=True,
                    sent_data=payload_data,
                    received_data=response,
                    latency_ms=latency
                ))
        
        # Check logs for expected patterns
        time.sleep(0.5)  # Let logs flush
        
        uplink_found = check_log_for_pattern(client_log, mode.expected_uplink_log)
        response_found = check_log_for_pattern(client_log, mode.expected_response_log) or \
                        check_log_for_pattern(server_log, mode.expected_response_log.replace("[UDP-RESPONSE]", "[UDP-RESPONSE]"))
        
        print(f"  Log check: uplink={uplink_found}, response={response_found}")
        
        if not uplink_found:
            print(f"  WARNING: Expected uplink log pattern '{mode.expected_uplink_log}' not found")
        if not response_found:
            print(f"  WARNING: Expected response log pattern '{mode.expected_response_log}' not found")
        
        # Print logs for debugging if any test failed
        if any(not r.success for r in results):
            print("\n  --- Client Log (last 50 lines) ---")
            try:
                with open(client_log, 'r') as f:
                    lines = f.readlines()
                    for line in lines[-50:]:
                        print(f"    {line.rstrip()}")
            except Exception as e:
                print(f"    Could not read: {e}")
            
            print("\n  --- Server Log (last 50 lines) ---")
            try:
                with open(server_log, 'r') as f:
                    lines = f.readlines()
                    for line in lines[-50:]:
                        print(f"    {line.rstrip()}")
            except Exception as e:
                print(f"    Could not read: {e}")
            
    finally:
        pm.stop_all()
        echo.stop()
        
        # Cleanup config files
        try:
            os.remove(client_config)
            os.remove(server_config)
        except:
            pass
    
    return results


def main():
    print("="*60)
    print("DNS Tunnel Comprehensive Test Suite")
    print("="*60)
    
    # Get project directory
    script_dir = Path(__file__).parent.absolute()
    project_dir = str(script_dir)
    
    print(f"Project directory: {project_dir}")
    
    # Build project
    if not build_project(project_dir):
        print("Failed to build project")
        sys.exit(1)
    
    # Run tests
    pm = ProcessManager()
    all_results: List[TestResult] = []
    
    try:
        for mode in TEST_MODES:
            results = run_test_mode(mode, project_dir, pm)
            all_results.extend(results)
            
    except KeyboardInterrupt:
        print("\nInterrupted by user")
    finally:
        pm.stop_all()
        pm.cleanup_logs()
    
    # Print summary
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    passed = sum(1 for r in all_results if r.success)
    failed = sum(1 for r in all_results if not r.success)
    
    for r in all_results:
        status = "PASS" if r.success else "FAIL"
        print(f"  [{status}] {r.name}", end="")
        if r.success:
            print(f" ({r.latency_ms:.1f}ms)")
        else:
            print(f" - {r.error}")
    
    print(f"\nTotal: {passed}/{len(all_results)} passed")
    
    if failed > 0:
        print("\nSome tests failed!")
        sys.exit(1)
    else:
        print("\nAll tests passed!")
        sys.exit(0)


if __name__ == "__main__":
    main()
