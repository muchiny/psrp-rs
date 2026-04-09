# -*- mode: ruby -*-
# vi: set ft=ruby :

# psrp-rs — Windows Server test VM for MS-PSRP integration testing
#
# Prerequisites:
#   1. Vagrant on Windows: winget install Hashicorp.Vagrant
#   2. Hyper-V enabled (WSL2 implies this)
#
# Usage from WSL2:
#   vagrant.exe up --provider=hyperv    # Create and start the VM
#   vagrant.exe ssh -c "ipconfig"       # Get the VM IP address
#   PSRP_INTEGRATION_HOST=<ip> \
#   PSRP_INTEGRATION_USER=vagrant \
#   PSRP_INTEGRATION_PASS=vagrant \
#     cargo test --test integration_real -- --ignored
#   vagrant.exe destroy -f              # Tear down
#
# The box is shared with winrm-rs — if you already have the winrm-rs VM,
# stop it before bringing this one up (they reuse the same underlying image
# but different hostnames/VM names).

Vagrant.configure("2") do |config|
  config.vm.define "psrp-test" do |win|
    # Windows Server 2025 Standard Evaluation (180 days, free)
    win.vm.box = "gusztavvargadr/windows-server-2025-standard"
    win.vm.hostname = "psrp-test"

    # WinRM communicator (Vagrant uses it to talk to the guest during provisioning)
    win.vm.communicator = "winrm"
    win.winrm.transport = :plaintext
    win.winrm.basic_auth_only = true
    win.winrm.port = 5985
    win.winrm.guest_port = 5985
    win.winrm.username = "vagrant"
    win.winrm.password = "vagrant"

    # Hyper-V provider
    win.vm.provider "hyperv" do |h|
      h.vmname = "psrp-rs-test"
      h.cpus = 2
      h.memory = 2048
      h.enable_virtualization_extensions = false
    end

    # Default Switch (no interactive prompt)
    win.vm.network "public_network", bridge: "Default Switch"

    # Disable SMB shared folders (avoids credential prompt)
    win.vm.synced_folder ".", "/vagrant", disabled: true

    # Provisioning: configure WinRM + PSRP
    win.vm.provision "shell", inline: <<-SHELL
      # Basic auth + unencrypted (for offline-dev HTTP testing).
      # For production you'd want HTTPS + NTLM/Kerberos.
      Set-Item -Path WSMan:\\localhost\\Service\\Auth\\Basic -Value $true
      Set-Item -Path WSMan:\\localhost\\Service\\AllowUnencrypted -Value $true

      # NTLM auth stays on (psrp-rs defaults to NTLM).
      Set-Item -Path WSMan:\\localhost\\Service\\Auth\\Negotiate -Value $true

      # Bump the per-shell memory budget so large CLIXML pipelines aren't
      # throttled by the default 150 MB cap.
      Set-Item -Path WSMan:\\localhost\\Shell\\MaxMemoryPerShellMB -Value 1024

      # Make sure PowerShell Remoting is actually enabled — this is what
      # `powershell.exe -s` (PSRP server mode) relies on.
      Enable-PSRemoting -Force -SkipNetworkProfileCheck

      # Firewall: allow WinRM HTTP inbound.
      New-NetFirewallRule -DisplayName "WinRM HTTP" -Direction Inbound `
        -LocalPort 5985 -Protocol TCP -Action Allow -ErrorAction SilentlyContinue

      Write-Host "psrp-rs test VM provisioning complete."
      Write-Host "WinRM: port 5985 (HTTP, Basic + NTLM)"
      Write-Host "User:  vagrant / vagrant"
      Write-Host "PSRP:  powershell.exe -s is ready via Enable-PSRemoting"
    SHELL
  end
end
