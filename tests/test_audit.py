import builtins
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from env_drift.audit import audit, report
from env_drift.cli import main


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, name, text):
        path = self.root/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def kinds(self):
        return {f['kind'] for f in audit(self.root)['findings']}

    def test_empty(self):
        self.assertEqual(audit(self.root)['verdict'], 'PASS')
        self.assertTrue(audit(self.root)['notes'])

    def test_missing_example(self):
        self.write('app.py', 'os.getenv("APP_KEY")')
        self.assertEqual(self.kinds(), {'missing-example'})

    def test_undocumented(self):
        self.write('.env.example', '')
        self.write('app.py', 'os.getenv("APP_KEY")')
        self.assertIn('undocumented-var', self.kinds())

    def test_stale_example(self):
        self.write('.env.example', 'OLD_KEY=do-not-print')
        self.assertEqual(self.kinds(), {'stale-example-var'})

    def test_stale_secret(self):
        self.write('.github/workflows/a.yml', 'token: ${{ secrets.OLD_KEY }}')
        self.assertEqual(self.kinds(), {'stale-ci-secret'})

    def test_unset_ci(self):
        self.write('app.py', 'os.getenv("APP_KEY")')
        self.write('Dockerfile', 'FROM scratch')
        self.assertIn('unset-in-ci', self.kinds())

    def test_env_never_opened(self):
        self.write('.env', 'FORBIDDEN_VALUE_SENTINEL')
        original = io.open
        original_builtin = builtins.open
        def guarded(file, *args, **kwargs):
            self.assertNotEqual(Path(file).name, '.env')
            return original(file, *args, **kwargs)
        def guarded_builtin(file, *args, **kwargs):
            self.assertNotEqual(Path(file).name, '.env')
            return original_builtin(file, *args, **kwargs)
        with patch('io.open', guarded), patch('builtins.open', guarded_builtin):
            result = audit(self.root)
        self.assertEqual(result['per_kind']['committed-env-file'], 1)
        self.assertNotIn('FORBIDDEN_VALUE_SENTINEL', json.dumps(result))
        self.assertIn('did not read it', result['findings'][0]['detail'])

    def test_other_dotenv_unread(self):
        self.write('.env.local', 'FORBIDDEN')
        with patch.object(Path, 'read_text', side_effect=AssertionError('read')):
            self.assertEqual(audit(self.root)['verdict'], 'PASS')

    def test_example_priority(self):
        self.write('.env.example', 'APP_KEY=x')
        self.write('.env.sample', 'OTHER_KEY=x')
        self.write('app.py', 'os.getenv("APP_KEY")')
        self.assertEqual(audit(self.root)['verdict'], 'PASS')

    def test_example_parser(self):
        self.write('.env.example', '# COMMENT=x\n\nexport APP_KEY="hidden"\nbad line\n')
        result = audit(self.root)
        self.assertEqual([f['claim'] for f in result['findings']], ['APP_KEY'])
        self.assertNotIn('hidden', json.dumps(result))

    def test_ci_nested(self):
        self.write('app.py', 'os.getenv("APP_KEY")')
        self.write('.env.example', 'APP_KEY=x')
        self.write('.github/workflows/a.yaml', 'jobs:\n  a:\n    env:\n      APP_KEY: private\n    steps:\n      - run: hello\n')
        self.assertEqual(audit(self.root)['verdict'], 'PASS')

    def test_ci_section_end(self):
        self.write('app.py', 'os.getenv("APP_KEY")')
        self.write('.github/workflows/a.yml', 'env:\n  OTHER: x\nnext:\n  APP_KEY: x\n')
        self.assertIn('unset-in-ci', self.kinds())

    def test_secret_supplies_code(self):
        self.write('app.py', 'os.getenv("APP_KEY")')
        self.write('.env.example', 'APP_KEY=x')
        self.write('.github/workflows/a.yml', 'token: ${{ secrets.APP_KEY }}')
        self.assertEqual(audit(self.root)['verdict'], 'PASS')

    def test_stale_example_ci_reference(self):
        self.write('.env.example', 'APP_KEY=x')
        self.write('.github/workflows/a.yml', 'env:\n  APP_KEY: x')
        self.assertEqual(audit(self.root)['verdict'], 'PASS')

    def test_invalid_utf8(self):
        (self.root/'app.py').write_bytes(b'\xff')
        result = audit(self.root)
        self.assertEqual(result['parse_error_count'], 1)
        self.assertEqual(result['verdict'], 'WARN')

    def test_unreadable(self):
        self.write('app.py', '')
        with patch.object(Path, 'read_text', side_effect=PermissionError):
            self.assertEqual(audit(self.root)['parse_error_count'], 1)

    def test_missing_path(self):
        with self.assertRaises(ValueError):
            audit(self.root/'missing')

    def test_file_path(self):
        with self.assertRaises(ValueError):
            audit(self.write('file', ''))

    def test_ignore_once(self):
        self.write('.env.example', 'APP_KEY=x')
        result = audit(self.root, ignore=['APP*', '*KEY'])
        self.assertEqual(result['ignored_count'], 1)
        self.assertEqual(result['verdict'], 'PASS')

    def test_ignore_filename(self):
        self.write('nested/.env', 'placeholder')
        self.assertEqual(audit(self.root, ignore=['nested/*'])['total'], 0)

    def test_medium_threshold(self):
        self.write('.env.example', 'APP_KEY=x')
        self.assertEqual(audit(self.root)['verdict'], 'WARN')
        self.assertEqual(audit(self.root, fail_on='medium')['verdict'], 'FAIL')

    def test_cap_and_totals(self):
        findings = [dict(file='a', line=i, kind='undocumented-var', claim='APP_KEY', severity='HIGH', detail='test') for i in range(501)]
        result = report(findings)
        self.assertEqual(len(result['findings']), 500)
        self.assertEqual(result['total'], 501)
        self.assertEqual(result['per_severity']['HIGH'], 501)
        self.assertTrue(result['truncated'])
        self.assertEqual(result['omitted_count'], 1)
        self.assertEqual(result['verdict'], 'FAIL')

    def test_dedup(self):
        self.write('.env.example', '')
        self.write('app.py', 'os.getenv("APP_KEY"); os.getenv("APP_KEY")')
        self.assertEqual(audit(self.root)['total'], 1)

    def test_sort(self):
        self.write('z.py', 'os.getenv("ZZ")')
        self.write('a.py', 'os.getenv("AA")')
        self.write('.env.example', '')
        self.assertEqual([f['file'] for f in audit(self.root)['findings']], ['a.py', 'z.py'])

    def test_symlink_directory(self):
        self.write('skip/app.py', 'os.getenv("APP_KEY")')
        (self.root/'linked').symlink_to(self.root/'skip', target_is_directory=True)
        self.assertEqual(audit(self.root)['total'], 1)

    def test_symlink_file(self):
        self.write('file.txt', 'os.getenv("APP_KEY")')
        (self.root/'app.py').symlink_to(self.root/'file.txt')
        self.assertEqual(audit(self.root)['total'], 0)

    def cli(self, *args):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            code = main(list(args))
        return code, stream.getvalue()

    def test_json(self):
        code, output = self.cli('audit', str(self.root), '--json')
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)['verdict'], 'PASS')

    def test_human_counts(self):
        _, output = self.cli('audit', str(self.root))
        for word in ('per_kind', 'per_severity', 'ignored_count', 'parse_error_count', 'truncated'):
            self.assertIn(word, output)

    def test_cli_ignore_repeat(self):
        self.write('.env.example', 'APP_KEY=x\nOTHER_KEY=x')
        code, output = self.cli('audit', str(self.root), '--json', '--ignore', 'APP*', '--ignore', 'OTHER*')
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output)['ignored_count'], 2)

    def test_cli_error(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            main(['audit', str(self.root/'missing')])
        self.assertEqual(error.exception.code, 2)

    def test_good_fixture(self):
        repo = Path(__file__).resolve().parents[1]/'examples/sample-repo/good'
        self.assertEqual(self.cli('audit', str(repo))[0], 0)

    def test_broken_fixture(self):
        repo = Path(__file__).resolve().parents[1]/'examples/sample-repo/broken'
        code, output = self.cli('audit', str(repo), '--json')
        self.assertEqual(code, 2)
        self.assertNotIn('example-only', output)
        self.assertEqual(json.loads(output)['per_severity']['HIGH'], 2)


def pattern_test(suffix, source, expected=True):
    def test(self):
        self.write('app'+suffix, source)
        self.write('.env.example', 'APP_KEY=x')
        kinds = self.kinds()
        self.assertEqual('stale-example-var' not in kinds, expected)
    return test

for index, (suffix, source, expected) in enumerate([
    ('.py', 'os.getenv("APP_KEY")', True),
    ('.py', "os.environ['APP_KEY']", True),
    ('.py', 'os.environ.get("APP_KEY", "fallback")', True),
    ('.js', 'process.env.APP_KEY', True),
    ('.ts', 'process.env["APP_KEY"]', True),
    ('.go', 'os.Getenv("APP_KEY")', True),
    ('.rs', 'env::var("APP_KEY")', True),
    ('.rs', 'std::env::var("APP_KEY")', True),
    ('.py', 'os.getenv("x")', False),
    ('.py', 'os.getenv("APP_KEYlower")', False),
    ('.js', 'process.env.APP_KEYlower', False),
    ('.js', 'process.env.APP_KEY$extra', False),
    ('.py', 'os.getenv("A")', False),
    ('.py', 'os.getenv(variable)', False),
    ('.txt', 'os.getenv("APP_KEY")', False),
]):
    setattr(AuditTests, 'test_pattern_%02d' % index, pattern_test(suffix, source, expected))

for index, directory in enumerate(['.git', 'node_modules', 'dist', '__pycache__', '.venv', 'venv']):
    def test(self, directory=directory):
        self.write(directory+'/app.py', 'os.getenv("APP_KEY")')
        self.assertEqual(audit(self.root)['total'], 0)
    setattr(AuditTests, 'test_skip_%02d' % index, test)

for index, text in enumerate(['ENV APP_KEY=x', 'ENV APP_KEY x']):
    def test(self, text=text):
        self.write('app.py', 'os.getenv("APP_KEY")')
        self.write('.env.example', 'APP_KEY=x')
        self.write('Dockerfile.dev', text)
        self.assertEqual(audit(self.root)['verdict'], 'PASS')
    setattr(AuditTests, 'test_docker_%02d' % index, test)
