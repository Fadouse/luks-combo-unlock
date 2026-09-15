{ config, lib, pkgs, utils, ... }:
let
  cfg = config.boot.initrd.luksComboUnlock;
  package = pkgs.callPackage ./package.nix {};
  settings = pkgs.writeText "luks-combo-unlock.conf" ''
    cryptsetup=${config.boot.initrd.systemd.package}/bin/systemd-cryptsetup
    root_device=${cfg.rootDevice}
    root_uuid=${cfg.rootUuid}
    manifest_hash=${cfg.manifestHash}
    cryptsetup_cli=${pkgs.cryptsetup}/bin/cryptsetup
    cryptenroll=${config.boot.initrd.systemd.package}/bin/systemd-cryptenroll
    ask_password=${config.boot.initrd.systemd.package}/bin/systemd-ask-password
    pcrlock=/var/lib/systemd/pcrlock.json
    state_dir=/etc/fde-combo-v2
    hid_identity=HID_ID=0003:00001050:00000402
  '';
in {
  options.boot.initrd.luksComboUnlock = {
    enable = lib.mkEnableOption "TPM and FIDO2 combination unlock";
    rootDevice = lib.mkOption { type = lib.types.str; };
    rootUuid = lib.mkOption { type = lib.types.strMatching "[0-9a-f-]{36}"; };
    manifestHash = lib.mkOption { type = lib.types.strMatching "[0-9a-f]{64}"; };
  };
  config = lib.mkIf cfg.enable {
    assertions = [{ assertion = config.boot.initrd.systemd.enable; message = "luksComboUnlock requires systemd initrd."; }];
    boot.initrd.secrets = {
      "/etc/fde-combo-v2/tpm.luks" = "/var/lib/fde-combo-v2/tpm.luks";
      "/etc/fde-combo-v2/manifest.bin" = "/var/lib/fde-combo-v2/manifest.bin";
    };
    boot.initrd.availableKernelModules = [ "loop" "usbhid" "hid_generic" ];
    boot.initrd.kernelModules = [ "loop" ];
    boot.initrd.systemd.storePaths = [ package settings "${config.boot.initrd.systemd.package}/bin/systemd-ask-password" ];
    boot.initrd.systemd.contents."/etc/luks-combo-unlock.conf".source = settings;
    boot.initrd.systemd.services.fde-combo-unlock = {
      description = "Unlock root with TPM and Security Key";
      wantedBy = [ "initrd.target" ];
      before = [ "systemd-cryptsetup@cryptroot.service" ];
      after = [ "systemd-udev-trigger.service" "systemd-tpm2-setup-early.service"
        "cryptsetup-pre.target" "dev-tpmrm0.device"
        "${utils.escapeSystemdPath cfg.rootDevice}.device" ];
      unitConfig.DefaultDependencies = false;
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${package}/bin/luks-combo-unlock unlock /etc/luks-combo-unlock.conf";
        RemainAfterExit = true;
        TimeoutStartSec = "300s";
        SyslogIdentifier = "luks";
        StandardOutput = "journal+console";
        StandardError = "journal+console";
        UMask = "0077";
        LimitCORE = 0;
        LimitMEMLOCK = "infinity";
        NoNewPrivileges = true;
        PrivateMounts = true;
      };
    };
  };
}
