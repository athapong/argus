"""Repository analysis and security assessment tools."""

from mcp.server.fastmcp import FastMCP, server
from mcp.server.fastmcp.resources import types
from pydantic import BaseModel
import os
import subprocess
from typing import List, Optional, Union
import tempfile
import shutil
from pathlib import Path
import hashlib
import gitdb
from git import Repo, GitCommandError

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

mcp = FastMCP(
    "Repository Tools",
    dependencies=[
        "GitPython",
        "gitdb",
    ]
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

