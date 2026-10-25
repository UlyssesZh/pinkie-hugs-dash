{
  pkgs ? import <nixpkgs> {
    config = {
      android_sdk.accept_license = true;
      allowUnfree = true;
    };
  },
}:
with pkgs;
mkShell {
  packages = [
    ruby_4_0
  ];
  shellHook =
    let
      buildToolsVersion = "37.0.0";
      androidComposition = androidenv.composeAndroidPackages {
        buildToolsVersions = [ buildToolsVersion ];
      };
    in
    ''
      export PATH=$PATH:${androidComposition.androidsdk}/libexec/android-sdk/build-tools/${buildToolsVersion}
      export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:${
        lib.makeLibraryPath [
          vips
          libogg
          libvorbis
        ]
      }
    '';
}
