# Third-Party Notices

LSMF's Debian-family release-candidate package redistributes the following
pinned binary Python wheels:

| Component | Version | License declared by wheel metadata | Upstream source |
| --- | --- | --- | --- |
| PySide6 | 6.11.1 | LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only | https://code.qt.io/cgit/pyside/pyside-setup.git/ |
| PySide6 Essentials / Qt libraries | 6.11.1 | LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only | https://code.qt.io/cgit/pyside/pyside-setup.git/ |
| Shiboken6 | 6.11.1 | LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only | https://code.qt.io/cgit/pyside/pyside-setup.git/ |

LSMF uses these components under the GNU Lesser General Public License version
3. The full license text is in [licenses/LGPL-3.0.txt](licenses/LGPL-3.0.txt) and
is copied into built packages. The components remain separate dynamically
loaded libraries under `/opt/lsmf/qt`; recipients may replace them with
compatible modified versions.

Qt and Qt for Python include additional third-party components with their own
notices. The authoritative version-specific licensing documentation and source
are maintained by the Qt Project:

- https://doc.qt.io/qtforpython-6/licenses.html
- https://doc.qt.io/qt-6/licensing.html
- https://code.qt.io/cgit/pyside/pyside-setup.git/
- https://code.qt.io/cgit/qt/

The wheel filenames and SHA-256 digests used for package construction are
recorded in `packaging/debian/pyside6-wheels.sha256`. This notice is a factual
inventory, not legal advice and not a change to any upstream license.
