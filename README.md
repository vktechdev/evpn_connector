# evpn-connector

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

A service for automating the management distributed switch or router based on EVPN standards


## Key Features

*   **EVPN Standards Support:**
    *  RFC 7432: BGP MPLS-Based Ethernet VPN
    *  RFC 8365: Network Virtualization Overlay
    *  RFC 7988: Ingress Replication Tunnels in Multicast VPN
    *  RFC 9135: Integrated Routing and Bridging in Ethernet VPN
    *  RFC 9136: IP Prefix Advertisement in Ethernet VPN
*   **Hardware Integration:** Interaction with the hardware switch and routers via EVPN
*   **GoBGP Integration:** Interaction with the gobgpd daemon to pull or push EVPN annouces
*   **OpenvSwitch Management:** Direct management of bridges and flows within the OpenvSwitch system
*   **Reconciliation Loop Design:** Built on a closed-loop control architecture to ensure fault tolerance and reduce the impact of external factors
*   **Configurability:** Flexible setup via INI daemon configuration files and JSON clients configuration files

## Documentation
The details of the EVPN's operation and evpn-connector daemon workflow are described in the [presentation](https://vkvideo.ru/video-164978780_456239752) (in Russian only).

## Installation & Quick Start

### Prerequisites

*   **Python 3.8**
*   **System Dependencies:**
    *   `gobgp` (for interaction via BGP within the EVPN control plane)
    *   `openvswitch-switch` (for interaction via VXLAN within the EVPN data plane)
*   **Permissions:** Requires `root` privileges for interaction with OpenvSwitch


1.  **Install dependencies:**

    On Ubuntu/Debian:
    ```bash
    sudo apt update
    sudo apt install openvswitch-switch openvswitch-common gobgpd
    ```
    On CentOS/RHEL:
    ```bash
    sudo yum install gobgp openvswitch
    # or for newer versions:
    # sudo dnf install gobgp openvswitch
    ```
2.  **(Optional) Install latest GoBGP from binary release:**
    ```bash
    wget https://github.com/osrg/gobgp/releases/download/v3.34.0/gobgp_3.34.0_linux_amd64.tar.gz
    mkdir gobgp
    tar -xf gobgp_3.34.0_linux_amd64.tar.gz -C gobgp/
    ```
3.  **(Recommended) Create a virtual environment:**
    Recommended installation gobgp versions >= v3.34
    ```bash
    python3 -m venv evpn
    source evpn/bin/activate
    pip install --upgrade pip setuptools
    ```
4.  **Install evpn-connector:**
    ```bash
    pip install evpn-connector
    ```
### Configuration

Before the first run, you need to create a configuration file.

1.  **GoBGP config:** Copy the example configuration file and adapt it to your environment.
    ```bash
    cp etc/gobgpd/gobgp.conf.sample /etc/gobgpd/gobgp.conf
    ```
    It is necessary to configure gobgp so that all nodes can exchange announces with afi-safi **"l2evpn-evpn"**

2.  **evpn-connector config:** Copy the example configuration file and adapt it to your environment.
    ```bash
    mkdir /etc/evpn_connector/
    cp etc/evpn_connector/logging.yaml /etc/evpn_connector/logging.yaml
    cp etc/evpn_connector/evpn_connector.cfg.sample /etc/evpn_connector/evpn_connector.conf
    ```
3.  **Edit `/etc/evpn_connector/evpn_connector.conf`:** Specify the necessary parameters:
    *   `[gobgp] section`: Settings for connecting to the GoBGP daemon
        *   `[gobgp] source_ip`: Source IP address for all VXLAN packets
    *   `[ovs] section`: Settings for OpenvSwitch dataplane parameters
        *   `[ovs] switch_name`: Name of switch created in OvS
    *   `[daemon] section`: Settings for evpn_connector daemon
        *   `[daemon] configs_dir`: Path to client configs

4.  **Client configs:** Create clients configs. Example config:
    * For L2 connectivity
        ```json
        {
        "cfg_type": "l2",           // Config type for L2 connectivity use "l2"
        "mac": "36:e7:a5:7e:0c:81", // MAC address of client
        "ip": "10.0.0.1",           // IP address of client
        "vni": 10,                  // VXLAN segment identifier
        "ofport": 1000,             // OpenFlow port number in current OpenvSwitch switch
        "type": "flat",             // OpenvSwitch port type. May be "flat" and "vlan"
        "tag": 0,                   // OpenvSwitch port segment identifier. Ignored on "flat"
        "imp_rt": ["65000:10"],     // List of imported BGP Route Targets
        "exp_rt": ["65000:10"]      // List of exported BGP Route Targets
        }
        ```
    * For L3 connectivity
        ```json
        {
        "cfg_type": "l3",           // Config type for L3 connectivity use "l3"
        "mac": "36:e7:a5:7e:0c:81", // MAC address of client
        "routes": ["10.0.0.1/32"],  // List of CIDR prefixes for this client
        "vni": 10,                  // VXLAN segment identifier
        "ofport": 1000,             // OpenFlow port number in current OpenvSwitch switch
        "type": "flat",             // OpenvSwitch port type. May be "flat" and "vlan"
        "tag": 0,                   // OpenvSwitch port segment identifier. Ignored on "flat"
        "imp_rt": ["65000:10"],     // List of imported BGP Route Targets
        "exp_rt": ["65000:10"]      // List of exported BGP Route Targets
        }
        ```
    Need create json config for all clients in **configs_dir**
    ```bash
    mkdir /var/lib/evpn_connector/client_configs/
    vim /var/lib/evpn_connector/client_configs/vm1.json
    ```
### Running the Service

Start the service by specifying the path to your configuration file:

1.  **Run GoBGP:**
    ```bash
    sudo gobgpd -f /etc/gobgpd/gobgp.conf
    ```
2.  **Run evpn-connector**
    ```bash
    source evpn/bin/activate
    evpn-connector --config-file /etc/evpn_connector/evpn_connector.conf --daemon-configs_dir "/var/lib/evpn_connector/client_configs/"
    ```
