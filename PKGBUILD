# Maintainer : vmavromatis <bill.mavromatis@protonmail.com>
# Contributors : https://github.com/vmavromatis/absolutely-proprietary/graphs/contributors
_pkgname=absolutely-proprietary
pkgname=${_pkgname}-git
pkgver=r0
pkgrel=1
pkgdesc="Find proprietary software installed through your system and language package managers"
arch=('any')
url="https://github.com/vmavromatis/${_pkgname}"
license=('GPL-3.0-or-later')
depends=('python' 'python-httpx2' 'python-license-expression' 'python-msgspec' 'python-pyudev')
makedepends=('git' 'python-build' 'python-installer' 'python-setuptools' 'python-wheel')
checkdepends=('python-pytest' 'python-hypothesis')
provides=("${_pkgname}")
conflicts=("${_pkgname}")
source=("git+${url}.git")
sha256sums=('SKIP')

pkgver() {
  cd "${_pkgname}"
  printf "r%s.%s" "$(git rev-list --count HEAD)" "$(git rev-parse --short HEAD)"
}

build() {
  cd "${_pkgname}"
  python -m build --wheel --no-isolation
}

check() {
  cd "${_pkgname}"
  python -m pytest -q -o addopts=''  # the repo's addopts need pytest-xdist and pytest-cov
}

package() {
  cd "${_pkgname}"
  python -m installer --destdir="$pkgdir" dist/*.whl
  install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
}
