{
  description = "plausiden-watchtower — log tailer + alerter + auto-fix loop (#315)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    crane = {
      url = "github:ipetkov/crane";
    };
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, crane, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        rustToolchain = pkgs.rust-bin.stable."1.83.0".default.override {
          extensions = [ "rust-src" ];
        };

        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        src = craneLib.cleanCargoSource ./.;

        commonArgs = {
          inherit src;
          strictDeps = true;
          # `journal` feature is REQUIRED for the binary to even start
          # (main.rs is #[cfg(feature = "journal")] gated). Pass it
          # through so the build matches what deploy/install.sh ships.
          cargoExtraArgs = "--features journal";
          buildInputs = with pkgs; [
            openssl
          ];
          nativeBuildInputs = with pkgs; [
            pkg-config
          ];
          doCheck = true;
          OPENSSL_NO_VENDOR = "1";
        };

        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        plausiden-watchtower = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
        });
      in
      {
        packages.default = plausiden-watchtower;
        packages.plausiden-watchtower = plausiden-watchtower;

        apps.default = flake-utils.lib.mkApp {
          drv = plausiden-watchtower;
        };

        devShells.default = pkgs.mkShell {
          inputsFrom = [ plausiden-watchtower ];
          packages = with pkgs; [
            rustToolchain
            cargo-watch
            cargo-edit
            rust-analyzer
          ];
          shellHook = ''
            echo "plausiden-watchtower devshell — Rust ${rustToolchain.version}"
          '';
        };

        checks = {
          inherit plausiden-watchtower;

          plausiden-watchtower-clippy = craneLib.cargoClippy (commonArgs // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "--features journal --all-targets -- --deny warnings";
          });

          plausiden-watchtower-test = craneLib.cargoTest (commonArgs // {
            inherit cargoArtifacts;
          });

          plausiden-watchtower-fmt = craneLib.cargoFmt {
            inherit src;
          };
        };
      }
    ) // {
      # NixOS module — drop into a NixOS configuration to deploy the
      # watchtower:
      #
      #   inputs.plausiden-watchtower.url = "github:thepictishbeast/plausiden-watchtower";
      #   imports = [ inputs.plausiden-watchtower.nixosModules.default ];
      #   services.plausiden-watchtower = {
      #     enable = true;
      #     ntfy = { url = "..."; topic = "..."; };
      #     email = { to = "ops@example.com"; };
      #   };
      #
      # Mirrors the systemd directives in
      # deploy/systemd/plausiden-watchtower.service.
      nixosModules.default = { config, lib, pkgs, ... }:
        let
          cfg = config.services.plausiden-watchtower;
          pkg = self.packages.${pkgs.system}.default;
        in
        {
          options.services.plausiden-watchtower = {
            enable = lib.mkEnableOption "PlausiDen Watchtower log tailer + alerter";

            units = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [
                "sacredvote"
                "sacredvote-identity"
                "sacredvote-zktls"
                "sacredvote-webauthn"
                "sacredvote-crypto"
                "sacredvote-analytics"
              ];
              description = ''
                systemd units to tail via `journalctl -f`. The default
                list matches every Sacred Vote service that emits chain
                logs; override if your stack uses different unit names.
              '';
            };

            heartbeat = {
              path = lib.mkOption {
                type = lib.types.str;
                default = "/var/lib/plausiden-watchtower/heartbeat";
                description = "Heartbeat file the daemon writes every interval.";
              };
              intervalSecs = lib.mkOption {
                type = lib.types.ints.between 10 600;
                default = 60;
                description = "How often the daemon writes the heartbeat file.";
              };
            };

            ntfy = {
              url = lib.mkOption {
                type = lib.types.nullOr lib.types.str;
                default = null;
                description = ''
                  Full URL of the ntfy server (e.g. http://127.0.0.1:8090).
                  Setting this enables the ntfy alert sink; absent =
                  sink disabled.
                '';
              };
              topic = lib.mkOption {
                type = lib.types.str;
                default = "sacredvote-watchtower";
                description = "ntfy topic to POST alerts to.";
              };
              ratePerMin = lib.mkOption {
                type = lib.types.ints.positive;
                default = 10;
                description = "Token-bucket capacity per minute.";
              };
            };

            email = {
              to = lib.mkOption {
                type = lib.types.nullOr lib.types.str;
                default = null;
                description = ''
                  Recipient for Page-severity alerts (Warn/Info never
                  email regardless of count). Setting this enables the
                  email sink; absent = sink disabled.
                '';
              };
              from = lib.mkOption {
                type = lib.types.str;
                default = "alerts@sacredvote.org";
                description = ''
                  Envelope sender. NEVER set this to tim@sacred.vote
                  (locked off-limits per the feedback memory).
                '';
              };
              bin = lib.mkOption {
                type = lib.types.str;
                default = "mail";
                description = "Path to a `mail`-compatible binary.";
              };
            };

            autoClaude = {
              enable = lib.mkEnableOption ''
                AutoClaude fix loop (default-OFF per the upstream
                "refuse to wake Claude on unknowns to avoid runaway
                spend" directive). When enabled you MUST also set
                `rules` + at least one `projectMap` entry.
              '';
              rules = lib.mkOption {
                type = lib.types.listOf lib.types.str;
                default = [ ];
                description = ''
                  Whitelist of rule keys that may trigger an AutoClaude
                  fix-run. Anything outside this list is logged at
                  debug and dropped.
                '';
              };
              projectMap = lib.mkOption {
                type = lib.types.attrsOf lib.types.path;
                default = { };
                description = ''
                  Map from log-chain name (e.g. "REGISTRATION") to the
                  repo path Claude should be spawned against. Alerts
                  whose chain isn't in this map are dropped (no path
                  guessing).
                '';
              };
              maxConcurrent = lib.mkOption {
                type = lib.types.ints.positive;
                default = 1;
                description = ''
                  Hard cap on in-flight Claude processes. Saturated
                  alerts are logged + skipped, NOT queued — queueing
                  would let a burst backlog hours of Claude time.
                '';
              };
            };

            logLevel = lib.mkOption {
              type = lib.types.str;
              default = "plausiden_watchtower=info,warn";
              description = "Rust tracing env filter.";
            };

            extraEnvironmentFile = lib.mkOption {
              type = lib.types.nullOr lib.types.path;
              default = null;
              description = ''
                Optional path to an env file containing sensitive
                tokens that should NOT live in the Nix store. Typical
                contents:
                  NTFY_TOKEN=...
                  WATCHTOWER_EMAIL_TO=...   (override the public value)
                Loaded via systemd `EnvironmentFile=`. The path is
                given to systemd verbatim — point it at a SOPS-nix
                output or a manually-managed `/etc/...` file.
              '';
            };
          };

          config = lib.mkIf cfg.enable {
            users.users.watchtower = {
              isSystemUser = true;
              group = "watchtower";
              # systemd-journal supplementary group lets the spawned
              # journalctl -f subprocesses see other services' logs.
              extraGroups = [ "systemd-journal" ];
              description = "PlausiDen Watchtower daemon user";
            };
            users.groups.watchtower = { };

            systemd.services.plausiden-watchtower = {
              description = "PlausiDen Watchtower (#315) — log tailer + alerter + auto-fix loop";
              after = [ "network-online.target" ];
              wants = [ "network-online.target" ];
              wantedBy = [ "multi-user.target" ];

              environment = {
                RUST_LOG = cfg.logLevel;
                WATCHTOWER_UNITS = lib.concatStringsSep "," cfg.units;
                WATCHTOWER_HEARTBEAT_PATH = cfg.heartbeat.path;
                WATCHTOWER_HEARTBEAT_INTERVAL_SECS = toString cfg.heartbeat.intervalSecs;
              } // lib.optionalAttrs (cfg.ntfy.url != null) {
                NTFY_URL = cfg.ntfy.url;
                WATCHTOWER_NTFY_TOPIC = cfg.ntfy.topic;
                WATCHTOWER_NTFY_RATE_PER_MIN = toString cfg.ntfy.ratePerMin;
              } // lib.optionalAttrs (cfg.email.to != null) {
                WATCHTOWER_EMAIL_TO = cfg.email.to;
                WATCHTOWER_EMAIL_FROM = cfg.email.from;
                WATCHTOWER_EMAIL_BIN = cfg.email.bin;
              } // lib.optionalAttrs cfg.autoClaude.enable {
                WATCHTOWER_AUTO_CLAUDE_ENABLE = "1";
                WATCHTOWER_AUTO_CLAUDE_RULES = lib.concatStringsSep "," cfg.autoClaude.rules;
                WATCHTOWER_AUTO_CLAUDE_MAX_CONCURRENT = toString cfg.autoClaude.maxConcurrent;
              } // (lib.mapAttrs'
                (chain: path: lib.nameValuePair
                  "WATCHTOWER_AUTO_CLAUDE_PROJECT_${lib.toUpper chain}"
                  (toString path))
                cfg.autoClaude.projectMap);

              serviceConfig = {
                Type = "simple";
                ExecStart = "${pkg}/bin/plausiden-watchtower";
                User = "watchtower";
                Group = "watchtower";
                SupplementaryGroups = [ "systemd-journal" ];
                Restart = "on-failure";
                RestartSec = "5s";
                TimeoutStopSec = "10s";

                # Operator-managed secrets (e.g. NTFY_TOKEN) live outside
                # the Nix store. `-` prefix = optional: missing file is
                # not a service-start error.
                EnvironmentFile = lib.optional (cfg.extraEnvironmentFile != null)
                  "-${toString cfg.extraEnvironmentFile}";

                # State dir — heartbeat + AutoClaude incidents + worktrees.
                StateDirectory = "plausiden-watchtower";
                StateDirectoryMode = "0750";

                # Hardening — mirror deploy/systemd/plausiden-watchtower.service.
                NoNewPrivileges = true;
                ProtectSystem = "strict";
                ProtectHome = true;
                PrivateTmp = true;
                PrivateDevices = true;
                ProtectKernelTunables = true;
                ProtectKernelModules = true;
                ProtectKernelLogs = true;
                ProtectClock = true;
                ProtectControlGroups = true;
                ProtectHostname = true;
                ProtectProc = "invisible";
                RestrictNamespaces = true;
                RestrictRealtime = true;
                RestrictSUIDSGID = true;
                LockPersonality = true;
                MemoryDenyWriteExecute = true;
                SystemCallArchitectures = "native";
                SystemCallFilter = [
                  "@system-service"
                  "~@mount @debug @cpu-emulation @obsolete @swap @raw-io @reboot"
                ];
                CapabilityBoundingSet = "";
                AmbientCapabilities = "";

                RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];

                MemoryMax = "512M";
                TasksMax = 128;
                CPUQuota = "50%";
                LimitNOFILE = 4096;

                ReadWritePaths = [ "/var/lib/plausiden-watchtower" ];
              };

            };
          };
        };
    };
}
