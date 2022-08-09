#!/bin/bash

# Run express install
source /dev/stdin <<< "$(wget -qO- https://raw.githubusercontent.com/openziti/ziti/release-next/quickstart/docker/image/ziti-cli-functions.sh)"; expressInstall

# Start the controller and router
startZitiController
waitForController

# Keep the container running to enable tests
echo -e "Setup complete, ready for testing with the following settings:"
echo -e "${ZITI_EDGE_CTRL_ADVERTISED_HOST_PORT}"
echo -e "${ZITI_EDGE_ROUTER_HOSTNAME}"
echo -e "${ZITI_EDGE_CONTROLLER_HOSTNAME}"

# Keep the container running forever
"${ZITI_BIN_DIR}/ziti-router" run "${ZITI_HOME_OS_SPECIFIC}/${ZITI_EDGE_ROUTER_HOSTNAME}.yaml"