Configuring demo env:

1. Download Debian 12 nocloud image:
    ```bash
    wget https://cdimage.debian.org/images/cloud/bookworm/latest/debian-12-nocloud-amd64.qcow2
    ```
2. Run virtual machines via virt-manager or qemu:
    ```
    Hostname: compute1, ip_address: 10.10.10.1 on enp1s0
    Hostname: compute2, ip_address: 10.10.10.2 on enp1s0
    ```
3. Install packages:
    ```bash
    sudo apt update
    sudo apt install build-essential zlib1g-dev libffi-dev libssl-dev libbz2-dev libreadline-dev libsqlite3-dev liblzma-dev libncurses-dev screen tcpdump openvswitch-switch openvswitch-common jq curl git wget
    ```
4. Install pyenv:
    ```bash
    curl -fsSL https://pyenv.run | bash
    ```
5. Add to end of `.bashrc` and reenter to bash:
    ```bash
    export PYENV_ROOT="$HOME/.pyenv"
    [[ -d $PYENV_ROOT/bin ]] && export PATH="$PYENV_ROOT/bin:$PATH"
    eval "$(pyenv init - bash)"
    export PATH="$HOME/gobgp:$PATH"
    bold=$(tput bold)
    red=$(tput setaf 1)
    green=$(tput setaf 2)
    blue=$(tput setaf 4)
    reset=$(tput sgr0)
    PS1='\[$red\]\h\[$reset\]:\[$bold\]\w\[$reset\]\$ '
    ```
6. Install python3.8 for evpn-connector:
    ```bash
    pyenv install 3.8.20
    pyenv global system 3.8
    ```
7. Create venv for evpn-connector and activate:
    ```bash
    python3.8 -m venv ~/evpn/
    source evpn/bin/activate
    ```
8. Install evpn-connector from pip
    ```bash
    pip install --upgrade pip setuptools
    pip install evpn-connector
    ```
9. Download and install GoBGP from binary:
    ```bash
    wget https://github.com/osrg/gobgp/releases/download/v3.34.0/gobgp_3.34.0_linux_amd64.tar.gz
    mkdir gobgp
    tar -xf gobgp_3.34.0_linux_amd64.tar.gz -C gobgp/
    rm gobgp_3.34.0_linux_amd64.tar.gz
    ```
10. Clone evpn-connector git repo:
    ```bash
    git clone https://github.com/vktechdev/evpn_connector
    ```
11. Copy configs for all daemons from repo (for each compute host separately):
    ```bash
    cp -r evpn_connector/docs/demo/compute1/* ~/

12. (Optional) Add routing to work with the border router
    ```bash
    ip route add 10.20.20.0/24 via 10.10.10.3
    ip route add 10.30.30.0/24 via 10.10.10.3
    ip route add 10.40.40.0/24 via 10.10.10.3
    ```
