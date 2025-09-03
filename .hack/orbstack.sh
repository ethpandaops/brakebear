#!/bin/bash

set -euo pipefail

VM_NAME="breakbear"
OS_IMAGE="ubuntu:24.10"

cleanup() {
    echo "Cleaning up VM '$VM_NAME'..."
    if orbctl info "$VM_NAME" &>/dev/null; then
        echo "Deleting VM '$VM_NAME'..."
        orb delete "$VM_NAME" -f
        echo "VM '$VM_NAME' deleted successfully!"
    else
        echo "VM '$VM_NAME' does not exist. Nothing to clean up."
    fi
}

# Check if cleanup argument is provided
if [[ "${1:-}" == "cleanup" ]]; then
    cleanup
    exit 0
fi

echo "Checking if VM '$VM_NAME' already exists..."

if orbctl info "$VM_NAME" &>/dev/null; then
    echo "VM '$VM_NAME' already exists. Skipping creation."
else
    echo "Creating OrbStack VM ..."
    orbctl create "$OS_IMAGE" "$VM_NAME" -c .hack/cloud-init.yaml
    # Add user to docker group
    ssh breakbear@orb "sudo usermod -aG docker $USER"
    # Change user default directory to $PWD
    ssh breakbear@orb "echo \"cd $PWD\" >> ~/.bashrc"
    echo "VM '$VM_NAME' created successfully!"

fi
echo "You can connect to it with: ssh $VM_NAME@orb"
echo "To cleanup the VM, run: $0 cleanup"
