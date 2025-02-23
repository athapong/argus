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

# Input schemas
class GitLabCredentials(BaseModel):
    api_key: str
    
class AnalyzeRepositoryInput(BaseModel):
    repo_url: str
    gitlab_credentials: Optional[GitLabCredentials] = None

class InspectFilesInput(BaseModel):
    repo_url: str
    file_paths: List[str]
    gitlab_credentials: Optional[GitLabCredentials] = None

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

def clone_repo(repo_url: str, gitlab_credentials: Optional[GitLabCredentials] = None) -> str:
    """Clone or retrieve an existing repository from cache and return its path."""
    # Generate cache directory name based on both URL and credentials
    cache_key = f"{repo_url}:{gitlab_credentials.api_key if gitlab_credentials else ''}"
    repo_hash = hashlib.sha256(cache_key.encode()).hexdigest()[:12]
    temp_dir = os.path.join(tempfile.gettempdir(), f"repo_cache_{repo_hash}")
    
    authenticated_url = get_authenticated_url(repo_url, gitlab_credentials)
    
    # If directory exists and is a valid git repo, return it
    if os.path.exists(temp_dir):
        try:
            repo = Repo(temp_dir)
            if not repo.bare and repo.remote().url == authenticated_url:
                return temp_dir
            # If URLs don't match, clean up and re-clone
            shutil.rmtree(temp_dir, ignore_errors=True)
        except:
            shutil.rmtree(temp_dir, ignore_errors=True)
    
    # Create directory and clone repository
    os.makedirs(temp_dir, exist_ok=True)
    try:
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

@mcp.tool()
def analyze_repository_structure(*, repo_url: str, gitlab_credentials: Optional[Union[str, dict]] = None) -> str:
    """
    Generate a tree representation of a repository's file structure.
    
    Args:
        repo_url: Repository URL to analyze
        gitlab_credentials: Optional GitLab token string or credentials dict
    """
    try:
        creds = create_gitlab_credentials(gitlab_credentials)
        repo_path = clone_repo(repo_url, creds)
        tree = get_directory_tree(repo_path)
        return tree
    except Exception as e:
        return f"Repository analysis failed: {str(e)}"

@mcp.tool()
def inspect_repository_files(*, repo_url: str, file_paths: List[str], gitlab_credentials: Optional[Union[str, dict]] = None) -> dict[str, str]:
    """Extract and return contents of specified repository files."""
    # Log the input arguments
    print(f"inspect_repository_files called with repo_url={repo_url}, file_paths={file_paths}, gitlab_credentials={gitlab_credentials}")
    
    try:
        creds = create_gitlab_credentials(gitlab_credentials)
        repo_path = clone_repo(repo_url, creds)
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
        repo_path = clone_repo(repo_url, creds)
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
    gitlab_credentials: Optional[Union[str, dict]] = None
) -> Dict[str, Any]:
    """
    Perform security scanning on a repository using Trivy.
    
    Args:
        repo_url: Repository URL to scan
        scan_type: Type of scan to perform (only "trivy" supported)
        gitlab_credentials: Optional GitLab credentials
        
    Returns:
        Dictionary containing scan results or errors
    """
    try:
        creds = create_gitlab_credentials(gitlab_credentials)
        repo_path = clone_repo(repo_url, creds)
        
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
