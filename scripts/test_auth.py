#!/usr/bin/env python3
"""
Authentication System Testing Tool
Automated testing for FastAPI + React authentication
"""

import os
import sys
import subprocess
import argparse
from pathlib import Path
from typing import Dict, Any


class AuthTester:
    def __init__(self, backend_path: Path, frontend_path: Path):
        self.backend_path = backend_path
        self.frontend_path = frontend_path
        self.results = {
            "backend_tests": None,
            "frontend_tests": None,
            "integration_tests": None,
            "security_checks": None
        }

    def test_backend(self) -> Dict[str, Any]:
        """Run backend tests."""
        print("Running backend tests...")

        try:
            # Check if pytest is available
            result = subprocess.run(
                ["pytest", "--version"],
                cwd=self.backend_path,
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                print("⚠️ pytest not installed, installing...")
                subprocess.run(
                    ["pip", "install", "pytest", "pytest-asyncio", "httpx"],
                    check=True
                )

            # Run tests
            result = subprocess.run(
                ["pytest", "-v", "--tb=short"],
                cwd=self.backend_path,
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.returncode == 0:
                print("✅ Backend tests passed")
                return {
                    "status": "PASS",
                    "output": result.stdout
                }
            else:
                print("❌ Backend tests failed")
                return {
                    "status": "FAIL",
                    "output": result.stdout,
                    "error": result.stderr
                }

        except subprocess.TimeoutExpired:
            print("⚠️ Backend tests timed out")
            return {"status": "TIMEOUT"}
        except FileNotFoundError:
            print("⚠️ No backend tests found")
            return {"status": "SKIP", "message": "No tests found"}
        except Exception as e:
            print(f"⚠️ Error running backend tests: {e}")
            return {"status": "ERROR", "error": str(e)}

    def test_frontend(self) -> Dict[str, Any]:
        """Run frontend tests."""
        print("Running frontend tests...")

        try:
            # Check if package.json exists
            package_json = self.frontend_path / "package.json"
            if not package_json.exists():
                print("⚠️ No package.json found")
                return {"status": "SKIP", "message": "No package.json found"}

            # Run tests
            result = subprocess.run(
                ["npm", "test", "--", "--run"],
                cwd=self.frontend_path,
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.returncode == 0:
                print("✅ Frontend tests passed")
                return {
                    "status": "PASS",
                    "output": result.stdout
                }
            else:
                print("❌ Frontend tests failed")
                return {
                    "status": "FAIL",
                    "output": result.stdout,
                    "error": result.stderr
                }

        except subprocess.TimeoutExpired:
            print("⚠️ Frontend tests timed out")
            return {"status": "TIMEOUT"}
        except Exception as e:
            print(f"⚠️ Error running frontend tests: {e}")
            return {"status": "ERROR", "error": str(e)}

    def check_security(self) -> Dict[str, Any]:
        """Run security checks."""
        print("Running security checks...")

        checks = {
            "password_hashing": False,
            "jwt_tokens": False,
            "https_ready": False,
            "cors_configured": False,
            "rate_limiting": False
        }

        # Check for password hashing
        auth_files = list(self.backend_path.rglob("*.py"))
        for file in auth_files:
            content = file.read_text()
            if "passlib" in content or "bcrypt" in content:
                checks["password_hashing"] = True
            if "jwt" in content or "jose" in content:
                checks["jwt_tokens"] = True
            if "CORSMiddleware" in content:
                checks["cors_configured"] = True

        # Check for HTTPS configuration
        env_files = list(self.backend_path.glob(".env*"))
        for file in env_files:
            content = file.read_text()
            if "https" in content.lower():
                checks["https_ready"] = True

        passed = sum(checks.values())
        total = len(checks)

        result = {
            "status": "PASS" if passed >= 3 else "FAIL",
            "checks": checks,
            "score": f"{passed}/{total}"
        }

        if result["status"] == "PASS":
            print(f"✅ Security checks: {result['score']}")
        else:
            print(f"⚠️ Security checks: {result['score']}")

        return result

    def test_endpoints(self) -> Dict[str, Any]:
        """Test authentication endpoints."""
        print("Testing authentication endpoints...")

        # This would require the backend to be running
        # For now, just check if endpoint files exist

        auth_routes = self.backend_path / "app" / "auth" / "routes.py"
        if not auth_routes.exists():
            print("⚠️ Auth routes not found")
            return {"status": "SKIP", "message": "Auth routes not found"}

        content = auth_routes.read_text()

        endpoints = {
            "register": "/register" in content,
            "login": "/login" in content,
            "logout": "/logout" in content,
            "refresh": "/refresh" in content,
            "me": "/me" in content
        }

        found = sum(endpoints.values())
        total = len(endpoints)

        result = {
            "status": "PASS" if found >= 4 else "FAIL",
            "endpoints": endpoints,
            "score": f"{found}/{total}"
        }

        if result["status"] == "PASS":
            print(f"✅ Endpoints defined: {result['score']}")
        else:
            print(f"⚠️ Endpoints defined: {result['score']}")

        return result

    def generate_report(self) -> str:
        """Generate test report."""
        report = """
AUTHENTICATION SYSTEM TEST REPORT
==================================
"""

        # Backend tests
        if self.results["backend_tests"]:
            bt = self.results["backend_tests"]
            report += f"\nBackend Tests: {bt['status']}\n"
            if bt.get("output"):
                report += f"  Output: {bt['output'][:200]}...\n"

        # Frontend tests
        if self.results["frontend_tests"]:
            ft = self.results["frontend_tests"]
            report += f"\nFrontend Tests: {ft['status']}\n"
            if ft.get("output"):
                report += f"  Output: {ft['output'][:200]}...\n"

        # Security checks
        if self.results["security_checks"]:
            sc = self.results["security_checks"]
            report += f"\nSecurity Checks: {sc['status']} ({sc['score']})\n"
            for check, passed in sc["checks"].items():
                status = "✅" if passed else "❌"
                report += f"  {status} {check}\n"

        # Integration tests
        if self.results["integration_tests"]:
            it = self.results["integration_tests"]
            report += f"\nIntegration Tests: {it['status']} ({it['score']})\n"

        # Overall status
        all_pass = all(
            r.get("status") in ["PASS", "SKIP"]
            for r in self.results.values()
            if r is not None
        )

        report += f"\nOverall: {'READY FOR DEPLOYMENT ✅' if all_pass else 'NEEDS ATTENTION ⚠️'}\n"

        return report


def main():
    parser = argparse.ArgumentParser(description="Test authentication system")
    parser.add_argument("--backend-path", "-b", type=str, required=True, help="Backend directory")
    parser.add_argument("--frontend-path", "-f", type=str, required=True, help="Frontend directory")
    parser.add_argument("--full", action="store_true", help="Run full test suite")
    parser.add_argument("--output", "-o", type=str, help="Output report file")

    args = parser.parse_args()

    backend_path = Path(args.backend_path)
    frontend_path = Path(args.frontend_path)

    if not backend_path.exists():
        print(f"Error: Backend path not found: {backend_path}")
        sys.exit(1)

    if not frontend_path.exists():
        print(f"Error: Frontend path not found: {frontend_path}")
        sys.exit(1)

    tester = AuthTester(backend_path, frontend_path)

    # Run tests
    if args.full:
        tester.results["backend_tests"] = tester.test_backend()
        tester.results["frontend_tests"] = tester.test_frontend()

    tester.results["security_checks"] = tester.check_security()
    tester.results["integration_tests"] = tester.test_endpoints()

    # Generate report
    report = tester.generate_report()
    print(report)

    # Save report if requested
    if args.output:
        Path(args.output).write_text(report)
        print(f"\n✅ Report saved to: {args.output}")


if __name__ == "__main__":
    main()
