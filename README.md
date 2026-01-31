# 2RTK NTRIP Caster

This is a high-performance NTRIP caster written in Python that supports NTRIP v1.0 and v2.0 protocols, managed through a modern web interface.

## Features

- **Web-based management**: Manage users and mount points directly in your browser.
- **SQLite backend**: Uses SQLite for persistent storage of user and mount point data.
- **RTCM Parsing**: Leverages the `pyrtcm` library to parse data, extracting message types and location information to automatically correct Source Table (STR) entries.
- **High Concurrency**: Supports 2000+ concurrent connections.
- **Modern Workflow**: Managed with `uv` for easy dependency management and execution.
- **Docker Support**: Ready for containerized deployment.

## Installation

### Using uv (Recommended)

1. Install [uv](https://github.com/astral-sh/uv).
2. Clone the repository.
3. Run the caster:
   ```bash
   uv run ntrip-caster
   ```

### Docker Deployment

```bash
docker run -d \
  --name ntrip-caster \
  -p 2101:2101 \
  -p 5757:5757 \
  2rtk/ntripcaster:latest
```

## Access

- **Web Management**: `http://localhost:5757`
- **NTRIP Service**: `ntrip://localhost:2101`
- **Default Account**: `admin` / `admin123` (Change the password immediately after first login!)

## Configuration

Main configuration is stored in `config.ini`. You can copy `config.ini.example` to get started.

```ini
[ntrip]
port = 2101
max_connections = 5000

[web]
port = 5757

[admin]
username = admin
password = admin123
```

## Development

The project is structured as a proper Python package. The source code is located in the `ntrip_caster/` directory.

### Running tests

```bash
uv run python tests/test_add_users.py
```

## Acknowledgments

This project stands on the shoulders of giants:
- **Flask** & **Flask-SocketIO**
- **pyrtcm** by semuconsulting
- **psutil** & **pyproj**

## License

Licensed under the Apache License 2.0. See `LICENSE` for details.
