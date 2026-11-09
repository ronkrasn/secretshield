class Secretshield < Formula
  include Language::Python::Virtualenv

  desc "Git hook & auto-remediation agent migrating secrets to Cloud Key Vaults"
  homepage "https://github.com/ronkrasnopolski/secretshield"
  url "https://github.com/ronkrasnopolski/secretshield/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "0efc641e2e469c3c762293eea6ad57a185d47a32ce7dac7b3aa85b2bcf56b74f"
  license "Apache-2.0"
  head "https://github.com/ronkrasnopolski/secretshield.git", branch: "main"

  depends_on "python@3.12"

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match "SecretShield v", shell_output("#{bin}/secretshield --version")
    assert_match "🛡️ SecretShield", shell_output("#{bin}/secretshield --help")
  end
end
