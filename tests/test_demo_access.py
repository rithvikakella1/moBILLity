"""Direct demo routes must authenticate even with demo/embedded query flags."""
import os
import tempfile
import unittest

os.environ['DATABASE_URL'] = ''
os.environ['DATABASE_FILE'] = tempfile.mktemp(prefix='mobillity-demo-test-', suffix='.db')
os.environ['OPENAI_API_KEY'] = 'test-key'
os.environ['JWT_SECRET_KEY'] = 'test-demo-secret'
os.environ['SESSION_SECRET_KEY'] = 'test-demo-session-secret'
os.environ['COOKIE_SECURE'] = 'false'
os.environ['ENVIRONMENT'] = 'development'

from fastapi.testclient import TestClient
import app as demo_app


class DemoAccessTests(unittest.TestCase):
    def test_direct_routes_require_authentication(self):
        client = TestClient(demo_app.app)
        for page, tab in [('demo', 'coder'), ('app', 'coder'), ('workflows', 'workflow'), ('patient', 'patient')]:
            for suffix in ['', '.html']:
                response = client.get(f'/{page}{suffix}?demo=1&embedded=1', follow_redirects=False)
                self.assertEqual(response.status_code, 303)
                self.assertEqual(response.headers['location'], f'/login.html?tab={tab}')
                self.assertEqual(response.headers['cache-control'], 'no-store')
                self.assertNotIn('iframe', response.text)

    def test_authenticated_routes_and_expired_session(self):
        with demo_app._db() as db:
            db.execute("DELETE FROM users WHERE email = ?", ('demo-access@example.com',))
            db.execute("INSERT INTO users(email, full_name, email_verified, created_at) VALUES (?, 'Demo Tester', 1, ?)", ('demo-access@example.com', demo_app._utcnow().isoformat()))
            user = db.execute('SELECT * FROM users WHERE email = ?', ('demo-access@example.com',)).fetchone()
        response = demo_app.Response()
        demo_app._set_auth_cookies(response, user)
        client = TestClient(demo_app.app)
        for cookie in response.headers.getlist('set-cookie'):
            name, value = cookie.split(';', 1)[0].split('=', 1)
            client.cookies.set(name, value)
        for path in ['/demo.html?tab=patient', '/app.html', '/workflows.html?demo=1', '/patient.html']:
            result = client.get(path, follow_redirects=False)
            self.assertEqual(result.status_code, 200)
            self.assertEqual(result.headers['x-frame-options'], 'SAMEORIGIN')
            self.assertEqual(result.headers['content-security-policy'], "frame-ancestors 'self'")
        with demo_app._db() as db:
            db.execute('UPDATE users SET session_version = session_version + 1 WHERE id = ?', (user['id'],))
        self.assertEqual(client.get('/demo.html', follow_redirects=False).status_code, 303)
        self.assertEqual(client.get('/api/me').status_code, 401)

    def test_tab_parameter_cannot_redirect_to_another_site(self):
        response = TestClient(demo_app.app).get('/demo.html?tab=https://example.com', follow_redirects=False)
        self.assertEqual(response.headers['location'], '/login.html?tab=coder')


if __name__ == '__main__':
    unittest.main()
