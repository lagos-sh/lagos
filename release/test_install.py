"""Test the real POSIX installer against local release fixtures, without network."""
import argparse
import hashlib
import importlib.util
import os
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('package', ROOT / 'release' / 'package.py')
packager = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packager)
BINARY = None
REAL_BINARY = None
VERSION = None


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix='lagos-installer-')
        self.addCleanup(self.scratch.cleanup)
        self.work = pathlib.Path(self.scratch.name)
        self.assets = self.work / 'assets'
        self.assets.mkdir()
        self.mock = self.work / 'commands'
        self.mock.mkdir()
        self.destination = self.work / 'user bin'
        self.destination.mkdir()
        self.existing = self.destination / 'lagos'
        self.existing.write_text('previous-installation')
        self.profile = self.work / '.profile'
        self.profile.write_text('profile-must-stay-unchanged')
        for target in packager.TARGETS:
            packager.package(BINARY, target, VERSION, self.assets)
        shutil.copyfile(ROOT / 'install.sh', self.assets / 'install.sh')
        packager.checksums(self.assets, VERSION)
        # Only the downloader and OS probe are mocked. tar, hash verification,
        # executable --version, staging and replacement use the real commands.
        curl = self.mock / 'curl'
        curl.write_text(f'''#!{sys.executable}
import os, pathlib, shutil, sys
args = sys.argv[1:]
with open(os.environ['REQUEST_LOG'], 'a') as log:
    log.write(args[-1] + '\\n')
if '--write-out' in args:
    sys.stdout.write(os.environ['LATEST_URL'])
else:
    source = pathlib.Path(os.environ['ASSETS']) / args[-1].rsplit('/', 1)[-1]
    if not source.exists():
        sys.exit(22)
    shutil.copyfile(source, args[args.index('--output') + 1])
''')
        curl.chmod(0o755)
        uname = self.mock / 'uname'
        uname.write_text('#!/bin/sh\ncase "$1" in -s) printf "%s\\n" "$MOCK_OS" ;; -m) printf "%s\\n" "$MOCK_ARCH" ;; esac\n')
        uname.chmod(0o755)
        sw_vers = self.mock / 'sw_vers'
        sw_vers.write_text('#!/bin/sh\nprintf "%s\\n" "${MOCK_MAC_VERSION:-14.0}"\n')
        sw_vers.chmod(0o755)
        self.env = dict(os.environ, HOME=str(self.work), PATH=f'{self.mock}{os.pathsep}{os.environ["PATH"]}', ASSETS=str(self.assets), REQUEST_LOG=str(self.work / 'requests'), LATEST_URL=f'https://github.com/lagos-sh/lagos/releases/tag/v{VERSION}', MOCK_OS='Linux', MOCK_ARCH='x86_64', TMPDIR=str(self.work))

    def run_install(self, *args, success=True):
        result = subprocess.run(['sh', str(ROOT / 'install.sh'), '--bin-dir', str(self.destination), *args], cwd=self.work, env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)
        self.assertEqual(self.profile.read_text(), 'profile-must-stay-unchanged')
        self.assertFalse(list(self.destination.glob('.lagos-install.*')))
        # All installer scratch directories must have been removed.
        self.assertEqual({p.name for p in self.work.iterdir()}, {'assets', 'commands', 'user bin', '.profile', 'requests'} if (self.work / 'requests').exists() else {'assets', 'commands', 'user bin', '.profile'})
        if not success:
            self.assertEqual(self.existing.read_text(), 'previous-installation')
        return result

    def requests(self):
        path = self.work / 'requests'
        return path.read_text().splitlines() if path.exists() else []

    def test_each_platform_selects_the_correct_archive(self):
        for system, arch, target in [('Linux', 'x86_64', packager.TARGETS[0]), ('Linux', 'arm64', packager.TARGETS[1]), ('Darwin', 'amd64', packager.TARGETS[2]), ('Darwin', 'aarch64', packager.TARGETS[3])]:
            with self.subTest(system=system, arch=arch):
                self.env.update(MOCK_OS=system, MOCK_ARCH=arch)
                self.run_install('--version', VERSION)
                self.assertIn(f'https://github.com/lagos-sh/lagos/releases/download/v{VERSION}/lagos-{VERSION}-{target}.tar.gz', self.requests())
                self.assertEqual(subprocess.check_output([str(self.existing), '--version'], text=True).strip(), f'lagos {VERSION}')
                self.assertEqual(self.existing.stat().st_mode & 0o777, 0o755)

    def test_latest_redirect_and_v_prefix_are_supported(self):
        self.run_install()
        self.assertEqual(self.requests()[0], 'https://github.com/lagos-sh/lagos/releases/latest')
        self.run_install('--version', f'v{VERSION}')

    @unittest.skipUnless(shutil.which('shasum'), 'shasum is not installed')
    def test_shasum_verifies_archives_without_coreutils(self):
        # Stock macOS has shasum but not sha256sum. Limit PATH to exercise
        # that environment while retaining the real extraction/install tools.
        for name in ['sh', 'tar', 'awk', 'grep', 'mktemp', 'chmod', 'cp', 'mv', 'mkdir', 'rm', 'shasum']:
            (self.mock / name).symlink_to(shutil.which(name))
        self.env['PATH'] = str(self.mock)
        self.env.update(MOCK_OS='Darwin', MOCK_ARCH='arm64')
        self.run_install('--version', VERSION)

    def test_checksum_mismatch_preserves_previous_installation(self):
        archive = self.assets / f'lagos-{VERSION}-{packager.TARGETS[0]}.tar.gz'
        archive.write_bytes(archive.read_bytes() + b'corrupt')
        result = self.run_install('--version', VERSION, success=False)
        self.assertIn('checksum mismatch', result.stderr)

    def test_missing_or_duplicate_checksums_are_rejected(self):
        sums = self.assets / 'SHA256SUMS'
        original = sums.read_text()
        name = f'lagos-{VERSION}-{packager.TARGETS[0]}.tar.gz'
        line = next(line for line in original.splitlines(True) if name in line)
        for changed in [original.replace(line, ''), original + line]:
            sums.write_text(changed)
            self.run_install('--version', VERSION, success=False)

    def test_unpublished_version_does_not_replace_existing_binary(self):
        self.run_install('--version', '99.99.99', success=False)

    def test_unsupported_system_or_architecture_does_not_download(self):
        for system, arch in [('FreeBSD', 'x86_64'), ('Linux', 'armv7l'), ('MINGW64_NT', 'AMD64')]:
            self.env.update(MOCK_OS=system, MOCK_ARCH=arch)
            self.run_install('--version', VERSION, success=False)
        self.assertEqual(self.requests(), [])

    def test_older_macos_is_rejected_before_downloading(self):
        self.env.update(MOCK_OS='Darwin', MOCK_ARCH='arm64', MOCK_MAC_VERSION='13.7')
        result = self.run_install('--version', VERSION, success=False)
        self.assertIn('macOS 14 or later', result.stderr)
        self.assertEqual(self.requests(), [])

    def test_invalid_versions_and_latest_redirects_do_not_download_archives(self):
        for value in ['../0.1.4', '0.1.4\nother', '0.1.4/evil', 'garbage', '']:
            self.run_install('--version', value, success=False)
        self.assertEqual(self.requests(), [])
        self.env['LATEST_URL'] = f'https://example.invalid/releases/tag/v{VERSION}'
        self.run_install(success=False)
        self.assertEqual(self.requests(), ['https://github.com/lagos-sh/lagos/releases/latest'])

    def test_archive_cannot_write_unselected_paths(self):
        archive = self.assets / f'lagos-{VERSION}-{packager.TARGETS[0]}.tar.gz'
        import io
        with tarfile.open(archive, 'w:gz') as tar:
            for name, body in [('lagos', BINARY.read_bytes()), ('../.profile', b'changed')]:
                info = tarfile.TarInfo(name)
                info.size = len(body)
                tar.addfile(info, io.BytesIO(body))
        packager.checksums(self.assets, VERSION)
        self.run_install('--version', VERSION)

    def test_archive_without_binary_and_mismatched_version_are_rejected(self):
        archive = self.assets / f'lagos-{VERSION}-{packager.TARGETS[0]}.tar.gz'
        with tarfile.open(archive, 'w:gz') as tar:
            tar.add(ROOT / 'LICENSE', arcname='LICENSE')
        packager.checksums(self.assets, VERSION)
        self.run_install('--version', VERSION, success=False)
        wrong = self.assets / f'lagos-99.99.99-{packager.TARGETS[0]}.tar.gz'
        packager.package(BINARY, packager.TARGETS[0], '99.99.99', self.assets)
        (self.assets / 'SHA256SUMS').write_text(f'{hashlib.sha256(wrong.read_bytes()).hexdigest()}  {wrong.name}\n')
        self.run_install('--version', '99.99.99', success=False)

    def test_release_manifest_requires_every_platform_and_rejects_extras(self):
        unexpected = self.assets / 'unexpected-file'
        unexpected.write_text('must-not-be-published')
        with self.assertRaises(ValueError):
            packager.checksums(self.assets, VERSION)
        unexpected.unlink()
        (self.assets / f'lagos-{VERSION}-{packager.TARGETS[3]}.tar.gz').unlink()
        with self.assertRaises(ValueError):
            packager.checksums(self.assets, VERSION)

    def test_real_executable_installs_from_a_checksum_verified_archive(self):
        packager.package(REAL_BINARY, packager.TARGETS[0], VERSION, self.assets)
        packager.checksums(self.assets, VERSION)
        self.run_install('--version', VERSION)
        self.assertEqual(self.existing.read_bytes(), REAL_BINARY.read_bytes())

    def test_packaged_binary_and_license_files_keep_their_content(self):
        for target in packager.TARGETS:
            with tarfile.open(self.assets / f'lagos-{VERSION}-{target}.tar.gz') as tar:
                self.assertEqual(tar.getnames(), ['lagos', 'LICENSE', 'NOTICE'])
                for name, source in [('lagos', BINARY), ('LICENSE', ROOT / 'LICENSE'), ('NOTICE', ROOT / 'NOTICE')]:
                    self.assertEqual(tar.extractfile(name).read(), source.read_bytes())
        first = self.assets / f'lagos-{VERSION}-{packager.TARGETS[0]}.tar.gz'
        previous = first.read_bytes()
        packager.package(BINARY, packager.TARGETS[0], VERSION, self.assets)
        self.assertEqual(first.read_bytes(), previous)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=pathlib.Path, required=True)
    args = parser.parse_args()
    REAL_BINARY = args.binary.resolve(strict=True)
    VERSION = subprocess.check_output([str(REAL_BINARY), '--version'], text=True).strip().removeprefix('lagos ')
    # Small executable fixtures cover OS selection and failure paths. One test
    # above installs the actual distributed executable without recompressing it
    # for every platform and every deliberately invalid archive.
    with tempfile.TemporaryDirectory(prefix='lagos-installer-binary-') as directory:
        BINARY = pathlib.Path(directory) / 'lagos'
        BINARY.write_text(f"#!/bin/sh\nprintf 'lagos {VERSION}\\n'\n")
        BINARY.chmod(0o755)
        unittest.main(argv=[sys.argv[0]], verbosity=2)
