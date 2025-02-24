"""Repository analysis and security assessment tools."""

from mcp.server.fastmcp import FastMCP, server
from mcp.server.fastmcp.resources import types
from pydantic import BaseModel
import os
import subprocess
from typing import List, Optional, Union, Dict, Any
import tempfile
import shutil
from pathlib import Path
import hashlib
import gitdb
from git import Repo, GitCommandError
import json
from enum import Enum
import xml.etree.ElementTree as ET
import platform
import urllib.request
import stat

def ensure_dependencies() -> None:
    """Ensure all required tools are installed."""
    # Check and install PMD
    if not is_pmd_installed():
        install_pmd()
    
    # Check and install Trivy
    if not is_trivy_installed():
        install_trivy()

def is_pmd_installed() -> bool:
    """Check if PMD is installed."""
    try:
        subprocess.run(["pmd", "--version"], capture_output=True)
        return True
    except FileNotFoundError:
        return False

def is_trivy_installed() -> bool:
    """Check if Trivy is installed."""
    try:
        subprocess.run(["trivy", "--version"], capture_output=True)
        return True
    except FileNotFoundError:
        return False

def install_pmd() -> None:
    """Install PMD."""
    system = platform.system().lower()
    if system == "darwin":  # macOS
        subprocess.run(["brew", "install", "pmd"], check=True)
    elif system == "linux":
        # Download and install PMD
        pmd_version = "7.0.0-rc4"
        pmd_url = f"https://github.com/pmd/pmd/releases/download/pmd_releases/{pmd_version}/pmd-bin-{pmd_version}.zip"
        install_dir = os.path.expanduser("~/.local/bin")
        
        # Create install directory if it doesn't exist
        os.makedirs(install_dir, exist_ok=True)
        
        # Download and extract PMD
        with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as tmp_file:
            urllib.request.urlretrieve(pmd_url, tmp_file.name)
            with zipfile.ZipFile(tmp_file.name, 'r') as zip_ref:
                zip_ref.extractall(install_dir)
        
        # Create symlink to PMD script
        pmd_script = os.path.join(install_dir, f"pmd-bin-{pmd_version}/bin/pmd")
        pmd_link = os.path.join(install_dir, "pmd")
        os.chmod(pmd_script, os.stat(pmd_script).st_mode | stat.S_IEXEC)
        if os.path.exists(pmd_link):
            os.remove(pmd_link)
        os.symlink(pmd_script, pmd_link)
        
        # Add to PATH if not already there
        if install_dir not in os.environ['PATH']:
            with open(os.path.expanduser("~/.bashrc"), "a") as bashrc:
                bashrc.write(f'\nexport PATH="{install_dir}:$PATH"\n')
    else:
        raise Exception(f"Unsupported operating system: {system}")

def install_trivy() -> None:
    """Install Trivy."""
    system = platform.system().lower()
    if system == "darwin":  # macOS
        subprocess.run(["brew", "install", "aquasecurity/trivy/trivy"], check=True)
    elif system == "linux":
        # Add Trivy repository and install
        subprocess.run([
            "sudo", "apt-get", "install", "wget", "apt-transport-https", "gnupg", "lsb-release"
        ], check=True)
        
        # Download and add Trivy GPG key
        subprocess.run([
            "wget", "-qO", "-", 
            "https://aquasecurity.github.io/trivy-repo/deb/public.key", 
            "|", "gpg", "--dearmor", "|",
            "sudo", "tee", "/usr/share/keyrings/trivy.gpg", ">", "/dev/null"
        ], check=True, shell=True)
        
        # Add Trivy repository
        subprocess.run([
            "echo", "deb [signed-by=/usr/share/keyrings/trivy.gpg]",
            "https://aquasecurity.github.io/trivy-repo/deb",
            "$(lsb_release -sc)", "main",
            "|", "sudo", "tee", "/etc/apt/sources.list.d/trivy.list"
        ], check=True, shell=True)
        
        # Update and install Trivy
        subprocess.run(["sudo", "apt-get", "update"], check=True)
        subprocess.run(["sudo", "apt-get", "install", "trivy", "-y"], check=True)
    else:
        raise Exception(f"Unsupported operating system: {system}")

# Initialize dependencies when module loads
ensure_dependencies()

# Input schemas
class GitLabCredentials(BaseModel):
    api_key: str
    
class AnalyzeRepositoryInput(BaseModel):
    repo_url: str
    gitlab_credentials: Optional[GitLabCredentials] = None
    branch: Optional[str] = None

class InspectFilesInput(BaseModel):
    repo_url: str
    file_paths: List[str]
    gitlab_credentials: Optional[GitLabCredentials] = None
    branch: Optional[str] = None

class EnumerateBranchesInput(BaseModel):
    repo_url: str
    gitlab_credentials: Optional[GitLabCredentials] = None

class DiffInput(BaseModel):
    repo_url: str
    source: Optional[str] = None  # Branch or commit ID, if None uses current
    target: Optional[str] = None  # Branch or commit ID, if None uses previous commit
    file_path: Optional[str] = None  # Specific file to diff, if None diffs all changes
    gitlab_credentials: Optional[GitLabCredentials] = None

# Add new input schemas
class SecurityScanInput(BaseModel):
    repo_url: str
    gitlab_credentials: Optional[GitLabCredentials] = None
    scan_type: Optional[str] = "trivy"  # Only trivy option remains
    branch: Optional[str] = None

class CodeQualityInput(BaseModel):
    repo_url: str
    language: str  # "go" or "java"
    gitlab_credentials: Optional[GitLabCredentials] = None
    branch: Optional[str] = None

mcp = FastMCP(
    "Repository Tools",
    dependencies=[
        "GitPython",
        "gitdb",
        "trivy",  # Only keep Trivy dependency
    ],
    log_level="WARNING"  # Set log level to WARNING to disable INFO logs
)

def get_authenticated_url(repo_url: str, gitlab_credentials: Optional[GitLabCredentials] = None) -> str:
    """Convert repository URL to include authentication if credentials provided."""
    if not gitlab_credentials:
        return repo_url
        
    # Handle GitLab URLs
    if "gitlab.com" in repo_url:
        if repo_url.startswith("https://"):
            # Convert https://gitlab.com/user/repo to https://oauth2:token@gitlab.com/user/repo
            return repo_url.replace("https://", f"https://oauth2:{gitlab_credentials.api_key}@")
        elif repo_url.startswith("git@"):
            # Convert git@gitlab.com:user/repo to https://oauth2:token@gitlab.com/user/repo
            return repo_url.replace("git@gitlab.com:", f"https://oauth2:{gitlab_credentials.api_key}@gitlab.com/")
    
    return repo_url

def clone_repo(repo_url: str, gitlab_credentials: Optional[GitLabCredentials] = None, branch: Optional[str] = None) -> str:
    """Clone or retrieve an existing repository from cache and return its path."""
    # Generate cache directory name based on URL, credentials and branch
    cache_key = f"{repo_url}:{gitlab_credentials.api_key if gitlab_credentials else ''}:{branch or 'default'}"
    repo_hash = hashlib.sha256(cache_key.encode()).hexdigest()[:12]
    temp_dir = os.path.join(tempfile.gettempdir(), f"repo_cache_{repo_hash}")
    
    authenticated_url = get_authenticated_url(repo_url, gitlab_credentials)
    
    # If directory exists and is a valid git repo, fetch updates
    if os.path.exists(temp_dir):
        try:
            repo = Repo(temp_dir)
            if not repo.bare and repo.remote().url == authenticated_url:
                repo.remote().fetch()
                if branch:
                    repo.git.checkout(branch)
                return temp_dir
            # If URLs don't match, clean up and re-clone
            shutil.rmtree(temp_dir, ignore_errors=True)
        except:
            shutil.rmtree(temp_dir, ignore_errors=True)
    
    # Create directory and clone repository
    os.makedirs(temp_dir, exist_ok=True)
    try:
        if branch:
            Repo.clone_from(authenticated_url, temp_dir, branch=branch)
        else:
            Repo.clone_from(authenticated_url, temp_dir)
        return temp_dir
    except Exception as e:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise Exception(f"Repository cloning failed: {str(e)}")

def get_directory_tree(path: str, prefix: str = "") -> str:
    """Generate a tree-like directory structure string"""
    output = ""
    entries = os.listdir(path)
    entries.sort()
    
    for i, entry in enumerate(entries):
        if entry.startswith('.git'):
            continue
            
        is_last = i == len(entries) - 1
        current_prefix = "└── " if is_last else "├── "
        next_prefix = "    " if is_last else "│   "
        
        entry_path = os.path.join(path, entry)
        output += prefix + current_prefix + entry + "\n"
        
        if os.path.isdir(entry_path):
            output += get_directory_tree(entry_path, prefix + next_prefix)
            
    return output

def create_gitlab_credentials(creds: Optional[Union[str, dict]]) -> Optional[GitLabCredentials]:
    """Convert various credential formats to GitLabCredentials."""
    if not creds:
        return None
    if isinstance(creds, str):
        return GitLabCredentials(api_key=creds)
    if isinstance(creds, dict):
        return GitLabCredentials(**creds)
    return None

def get_diff_changes(repo_path: str, source: Optional[str], target: Optional[str], file_path: Optional[str] = None) -> str:
    """Get diff between two commits/branches."""
    try:
        repo = Repo(repo_path)
        # Handle source
        if source:
            source_commit = repo.commit(source)
        else:
            source_commit = repo.head.commit

        # Handle target
        if target:
            target_commit = repo.commit(target)
        else:
            target_commit = source_commit.parents[0] if source_commit.parents else None
            if not target_commit:
                return "No previous commit found to compare with."

        # Generate diff
        if file_path:
            diff = repo.git.diff(target_commit, source_commit, '--', file_path)
        else:
            diff = repo.git.diff(target_commit, source_commit)

        return diff if diff else "No changes found."

    except GitCommandError as e:
        return f"Git diff failed: {str(e)}"
    except Exception as e:
        return f"Error generating diff: {str(e)}"

def run_trivy_scan(repo_path: str) -> Dict[str, Any]:
    """Run Trivy vulnerability scanner on repository."""
    try:
        result = subprocess.run(
            ["trivy", "fs", "--format", "json", repo_path],
            capture_output=True,
            text=True,
            check=True
        )
        return json.loads(result.stdout)
    except subprocess.CalledProcessError as e:
        return {"error": f"Trivy scan failed: {e.stderr}"}
    except json.JSONDecodeError:
        return {"error": "Failed to parse Trivy output"}
    except FileNotFoundError:
        return {"error": "Trivy not installed. Please install Trivy first."}

def run_gocyclo_analysis(repo_path: str) -> Dict[str, Any]:
    """Run cyclomatic complexity analysis on Go code."""
    try:
        result = subprocess.run(
            ["gocyclo", "-avg", "-over=10", "."],
            cwd=repo_path,
            capture_output=True,
            text=True
        )
        
        metrics = {
            "cyclomatic_complexity": [],
            "average_complexity": 0,
            "high_complexity_functions": 0
        }
        
        if result.stdout:
            lines = result.stdout.strip().split('\n')
            total_complexity = 0
            for line in lines:
                if line:
                    parts = line.split()
                    if len(parts) >= 4:
                        complexity = int(parts[0])
                        function_name = parts[-1]
                        file_path = parts[-2]
                        metrics["cyclomatic_complexity"].append({
                            "complexity": complexity,
                            "function": function_name,
                            "file": file_path
                        })
                        total_complexity += complexity
                        if complexity > 10:
                            metrics["high_complexity_functions"] += 1
                            
            if len(lines) > 0:
                metrics["average_complexity"] = total_complexity / len(lines)
                
        return metrics
    except FileNotFoundError:
        return {"error": "gocyclo not installed. Please install with: go install github.com/fzipp/gocyclo/cmd/gocyclo@latest"}
    except Exception as e:
        return {"error": f"Failed to run gocyclo: {str(e)}"}

def run_pmd_analysis(repo_path: str) -> Dict[str, Any]:
    """Run PMD static code analysis on Java code and return raw output."""
    try:
        # Create temporary file for PMD output
        with tempfile.NamedTemporaryFile(suffix='.xml', delete=False) as tmp_file:
            output_path = tmp_file.name
            
        # Run PMD with output to file
        result = subprocess.run(
            [
                "pmd",
                "check",
                "-d", repo_path,
                "-R", "rulesets/java/quickstart.xml",
                "-f", "xml",
                "-r", output_path
            ],
            capture_output=True,
            text=True
        )
        
        try:
            with open(output_path, 'r') as f:
                xml_content = f.read()
            return {"raw_output": xml_content}
        finally:
            os.unlink(output_path)
                
    except FileNotFoundError:
        return {"error": "PMD not installed. Please install PMD from https://pmd.github.io/"}
    except Exception as e:
        return {"error": f"Failed to run PMD: {str(e)}"}

@mcp.tool()
def analyze_repository_structure(*, repo_url: str, gitlab_credentials: Optional[Union[str, dict]] = None, branch: Optional[str] = None) -> str:
    """
    Generate a tree representation of a repository's file structure.
    
    Args:
        repo_url: Repository URL to analyze
        gitlab_credentials: Optional GitLab token string or credentials dict
        branch: Optional branch name to clone
    """
    try:
        creds = create_gitlab_credentials(gitlab_credentials)
        repo_path = clone_repo(repo_url, creds, branch)
        tree = get_directory_tree(repo_path)
        return tree
    except Exception as e:
        return f"Repository analysis failed: {str(e)}"

@mcp.tool()
def inspect_repository_files(*, repo_url: str, file_paths: List[str], gitlab_credentials: Optional[Union[str, dict]] = None, branch: Optional[str] = None) -> dict[str, str]:
    """Extract and return contents of specified repository files."""
    # Log the input arguments
    print(f"inspect_repository_files called with repo_url={repo_url}, file_paths={file_paths}, gitlab_credentials={gitlab_credentials}")
    
    try:
        creds = create_gitlab_credentials(gitlab_credentials)
        repo_path = clone_repo(repo_url, creds, branch)
        results = {}
        
        for file_path in file_paths:
            full_path = os.path.join(repo_path, file_path)
            
            # Check if file exists
            if not os.path.isfile(full_path):
                results[file_path] = f"Error: File not found"
                continue
                
            try:
                with open(full_path, 'r', encoding='utf-8') as f:
                    results[file_path] = f.read()
            except Exception as e:
                results[file_path] = f"Error reading file: {str(e)}"
        
        return results
            
    except Exception as e:
        return {"error": f"Repository inspection failed: {str(e)}"}

@mcp.tool()
def enumerate_branches(*, repo_url: str, gitlab_credentials: Optional[Union[str, dict]] = None) -> List[str]:
    """Retrieve all branch names from a repository."""
    try:
        creds = create_gitlab_credentials(gitlab_credentials)
        repo_path = clone_repo(repo_url, creds)
        repo = Repo(repo_path)
        
        # Get list of branches
        branches = [branch.name for branch in repo.branches]
        return branches
            
    except Exception as e:
        return [f"Branch enumeration failed: {str(e)}"]

@mcp.tool()
def compare_git_changes(*, 
    repo_url: str, 
    source: Optional[str] = None, 
    target: Optional[str] = None,
    file_path: Optional[str] = None,
    gitlab_credentials: Optional[Union[str, dict]] = None
) -> str:
    """
    Compare changes between git commits or branches.
    
    Args:
        repo_url: Repository URL
        source: Source branch/commit (default: current HEAD)
        target: Target branch/commit (default: previous commit)
        file_path: Specific file to compare (optional)
        gitlab_credentials: Optional GitLab credentials
    """
    try:
        creds = create_gitlab_credentials(gitlab_credentials)
        repo_path = clone_repo(repo_url, creds)
        return get_diff_changes(repo_path, source, target, file_path)
        
    except Exception as e:
        return f"Comparison failed: {str(e)}"

@mcp.tool()
def get_commit_history(*, 
    repo_url: str, 
    branch: Optional[str] = None,
    max_count: int = 10,
    gitlab_credentials: Optional[Union[str, dict]] = None
) -> List[dict]:
    """
    Get commit history for a repository branch.
    
    Args:
        repo_url: Repository URL
        branch: Branch name (default: current branch)
        max_count: Maximum number of commits to return
        gitlab_credentials: Optional GitLab credentials
    """
    try:
        creds = create_gitlab_credentials(gitlab_credentials)
        repo_path = clone_repo(repo_url, creds, branch)
        repo = Repo(repo_path)
        
        if (branch):
            repo.git.checkout(branch)
            
        commits = []
        for commit in repo.iter_commits(max_count=max_count):
            commits.append({
                'hash': commit.hexsha,
                'author': f"{commit.author.name} <{commit.author.email}>",
                'date': commit.committed_datetime.isoformat(),
                'message': commit.message.strip()
            })
            
        return commits
            
    except Exception as e:
        return [{'error': f"Failed to get commit history: {str(e)}"}]

@mcp.tool()
def security_scan_repository(*, 
    repo_url: str,
    scan_type: str = "trivy",
    gitlab_credentials: Optional[Union[str, dict]] = None,
    branch: Optional[str] = None
) -> Dict[str, Any]:
    """
    Perform security scanning on a repository using Trivy.
    
    Args:
        repo_url: Repository URL to scan
        scan_type: Type of scan to perform (only "trivy" supported)
        gitlab_credentials: Optional GitLab credentials
        branch: Optional branch name to clone
        
    Returns:
        Dictionary containing scan results or errors
    """
    try:
        creds = create_gitlab_credentials(gitlab_credentials)
        repo_path = clone_repo(repo_url, creds, branch)
        
        if scan_type != "trivy":
            return {"error": "Only Trivy scanning is supported"}
            
        return {"trivy_scan": run_trivy_scan(repo_path)}
    except Exception as e:
        return {"error": f"Security scan failed: {str(e)}"}

@mcp.tool()
def fetch_all_branches(*, repo_url: str, gitlab_credentials: Optional[Union[str, dict]] = None) -> Dict[str, Any]:
    """
    Fetch all branches from a repository and ensure they are up to date.
    
    Args:
        repo_url: Repository URL to fetch from
        gitlab_credentials: Optional GitLab credentials
        
    Returns:
        Dictionary containing branch information or error
    """
    try:
        creds = create_gitlab_credentials(gitlab_credentials)
        repo_path = clone_repo(repo_url, creds)
        repo = Repo(repo_path)
        
        # Fetch all remotes and their branches
        for remote in repo.remotes:
            remote.fetch()
            
        # Get all branches (both local and remote)
        branches = {
            "local": [branch.name for branch in repo.heads],
            "remote": [ref.name for ref in repo.remote().refs if not ref.name.endswith('/HEAD')],
            "current": repo.active_branch.name
        }
        
        return {
            "status": "success",
            "branches": branches
        }
            
    except Exception as e:
        return {
            "status": "error",
            "error": f"Failed to fetch branches: {str(e)}"
        }

@mcp.prompt()
def analyze_pmd_violations(pmd_output: str) -> str:
    return f"""As a seasoned software engineer, meticulously review the code quality analysis results generated by PMD. Craft a comprehensive, professional, and technically detailed summary that encompasses the following aspects:
1. Provide an overall assessment of the codebase's health, highlighting the general adherence to coding standards and best practices.
2. Identify and emphasize the most critical issues that demand immediate attention, detailing their potential impact on system stability, performance, and security.
3. Analyze and describe any recurring patterns or trends in the issues found, offering insights into common pitfalls or areas of weakness in the code.
4. Offer specific, actionable recommendations for improvement, suggesting concrete steps to remediate identified issues and enhance code quality.
5. Prioritize the issues in a logical order for addressing them, balancing urgency, impact, and effort required for resolution.

PMD output:
{pmd_output}"""

@mcp.tool()
def analyze_code_quality(*, 
    repo_url: str,
    language: str,
    gitlab_credentials: Optional[Union[str, dict]] = None,
    branch: Optional[str] = None
) -> Dict[str, Any]:
    """
    Analyze code quality and provide AI-generated summary.
    
    Args:
        repo_url: Repository URL
        language: Programming language ("go" or "java")
        gitlab_credentials: Optional GitLab credentials
        branch: Optional branch name to clone
        
    Returns:
        Dictionary containing analysis results and AI summary
    """
    try:
        creds = create_gitlab_credentials(gitlab_credentials)
        repo_path = clone_repo(repo_url, creds, branch)
        
        if language.lower() == "go":
            return {
                "status": "success",
                "metrics": run_gocyclo_analysis(repo_path)
            }
        elif language.lower() == "java":
            result = run_pmd_analysis(repo_path)
            if "error" in result:
                return {"status": "error", "error": result["error"]}
            
            # For each violation, try to read the actual file content
            violations = ET.fromstring(result["raw_output"])
            for file_elem in violations.findall(".//file"):
                file_path = file_elem.get("name")
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                        # Add file content to XML
                        file_elem.set("content", content)
                except:
                    pass
            
            # Convert back to string with file contents
            result["raw_output"] = ET.tostring(violations, encoding='unicode')
            
            # Get AI analysis of PMD results
            ai_analysis = mcp.call_tool("analyze_pmd_violations", pmd_output=result["raw_output"])
            
            return {
                "status": "success",
                "pmd_results": result,
                "analysis": ai_analysis
            }
            
        else:
            return {
                "status": "error",
                "error": f"Unsupported language: {language}. Supported languages: go, java"
            }
            
    except Exception as e:
        return {
            "status": "error",
            "error": f"Code quality analysis failed: {str(e)}"
        }
