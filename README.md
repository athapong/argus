# Argus

A Model Context Protocol (MCP) server for analyzing GitLab repositories and performing security assessments.

## Configuration

```json
{
    "mcpServers": {
        "argus": {
            "host": "0.0.0.0",
            "port": 8000
        }
    }
}
```

## Usage

The server provides the following tools:
- `git_directory_structure`: Returns repository structure
- `git_read_important_files`: Reads specified files
- `list_branches`: Lists all repository branches

