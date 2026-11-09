class Secretshield < Formula
  include Language::Python::Virtualenv

  desc "Git hook & auto-remediation agent migrating secrets to Cloud Key Vaults"
  homepage "https://github.com/ronkrasn/secretshield"
  url "https://github.com/ronkrasn/secretshield/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "c3df0ba225b803b632695ca2ad59fcbd5c2908972f106e6b5b1c2d97a0f1796e"
  license "Apache-2.0"
  head "https://github.com/ronkrasn/secretshield.git", branch: "main"

  depends_on "python@3.12"

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match "SecretShield v", shell_output("#{bin}/secretshield --version")
    assert_match "🛡️ SecretShield", shell_output("#{bin}/secretshield --help")
  end
end
