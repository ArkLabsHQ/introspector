{
  description = "ArkadeScript Emulator Signer Service";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    enclave.url = "github:ArkLabsHQ/enclave?rev=280106ed3741c70b6a0b07f3311c0db51014d66f";
  };

  outputs =
    {
      nixpkgs,
      enclave,
      self,
    }:
    let
      enclaveSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      allSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
        "x86_64-darwin"
      ];

      forSystems =
        systems: f:
        nixpkgs.lib.genAttrs systems (
          system:
          f {
            inherit system;
            pkgs = import nixpkgs { inherit system; };
          }
        );

      secretsConfig = builtins.toJSON [
        {
          name = "secret-key";
          env_var = "EMULATOR_SECRET_KEY";
        }
      ];
    in
    {
      packages =
        nixpkgs.lib.recursiveUpdate
          (forSystems allSystems (
            { pkgs, system, ... }:
            {
              emulator = pkgs.buildGoModule (finalAttrs: {
                pname = "emulator";
                version = "0.0.6-rc.0";
                src = ./.;
                subPackages = [ "cmd" ];
                vendorHash = "sha256-tgtJcBT27dPQaPNZ9RVCBN6JqMTeJ84yPasWqZCYbp0=";
                env.CGO_ENABLED = "0";
                buildFlags = [
                  "-trimpath"
                ];
                ldflags = [
                  "-X github.com/arkade-os/emulator/runtime.Version=${finalAttrs.version}"
                ];
                tags = [ "netgo" ];
                postInstall = ''
                  mv $out/bin/cmd $out/bin/${finalAttrs.pname}
                '';
              });
              default = self.packages.${system}.emulator;
            }
          ))
          (
            forSystems enclaveSystems (
              { pkgs, system, ... }:
              {
                eif = enclave.lib.buildEif {
                  inherit pkgs;
                  app = self.packages.${system}.emulator;
                  env = {
                    ENCLAVE_DEPLOYMENT = "prod";
                    ENCLAVE_APP_NAME = "myapp";
                    ENCLAVE_KMS_KEY_LOCKED = true;
                    ENCLAVE_MIGRATION_COOLDOWN = "${14 * 24}h"; # two weeks
                    ENCLAVE_MIGRATION_INTENT_RETENTION = "${10 * 365 * 24}h"; # 10 years
                    ENCLAVE_SECRETS_CONFIG = secretsConfig;
                    ENCLAVE_PREVIOUS_PCR0 = "genesis";
                  };
                };

                eifDev = enclave.lib.buildEif {
                  inherit pkgs;
                  app = self.packages.${system}.emulator;
                  env = {
                    ENCLAVE_DEPLOYMENT = "dev";
                    ENCLAVE_APP_NAME = "myapp";
                    ENCLAVE_KMS_KEY_LOCKED = false;
                    ENCLAVE_MIGRATION_COOLDOWN = "0s"; # instant
                    ENCLAVE_MIGRATION_INTENT_RETENTION = "1s";
                    ENCLAVE_SECRETS_CONFIG = secretsConfig;
                    ENCLAVE_PREVIOUS_PCR0 = "genesis";
                  };
                };
              }
            )
          );
    };
}
