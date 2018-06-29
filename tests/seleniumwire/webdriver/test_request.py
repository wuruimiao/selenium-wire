import uuid
from unittest import TestCase
from unittest.mock import Mock

from seleniumwire.webdriver.request import InspectRequestsMixin, Request, Response


class Driver(InspectRequestsMixin):
    def __init__(self, client):
        self._client = client


class InspectRequestsMixinTest(TestCase):

    def test_get_requests(self):
        mock_client = Mock()
        driver = Driver(mock_client)
        driver.requests

        mock_client.requests.assert_called_once_with()

    def test_delete_requests(self):
        mock_client = Mock()
        driver = Driver(mock_client)
        del driver.requests

        mock_client.clear_requests.assert_called_once_with()

    def test_set_requests(self):
        driver = Driver(Mock())

        with self.assertRaises(AttributeError):
            driver.requests = ['some request']


class RequestTest(TestCase):

    def test_create_request(self):
        data = self._request_data()

        request = Request(data, Mock())

        self.assertEqual(request.method, 'GET'),
        self.assertEqual(request.path, 'http://www.example.com/some/path/')
        self.assertEqual(len(request.headers), 3)
        self.assertEqual(request.headers['Host'], 'www.example.com')
        self.assertIsNone(request.response)

    def test_request_repr(self):
        data = self._request_data()

        request = Request(data, Mock())

        self.assertEqual(repr(request), 'Request({})'.format(data))

    def test_request_str(self):
        data = self._request_data()

        request = Request(data, Mock())

        self.assertEqual(str(request), 'http://www.example.com/some/path/'.format(data))

    def test_create_request_with_response(self):
        data = self._request_data()
        data['response'] = self._response_data()

        request = Request(data, Mock())

        self.assertIsInstance(request.response, Response)

    def test_load_request_body(self):
        mock_client = Mock()
        mock_client.request_body.return_value = b'the body'
        data = self._request_data()

        request = Request(data, mock_client)
        body = request.body

        self.assertEqual(body, b'the body')
        mock_client.request_body.assert_called_once_with(data['id'])

    def test_load_request_body_uses_cached_data(self):
        mock_client = Mock()
        mock_client.request_body.return_value = b'the body'
        data = self._request_data()

        request = Request(data, mock_client)
        request.body  # Retrieves the body
        body = request.body  # Uses the previously retrieved body

        self.assertEqual(body, b'the body')
        mock_client.request_body.assert_called_once_with(data['id'])

    def _request_data(self):
        data = {
            'id': uuid.uuid4(),
            'method': 'GET',
            'path': 'http://www.example.com/some/path/',
            'headers': {
                'Accept': '*/*',
                'Host': 'www.example.com',
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0'
            },
            'response': None
        }

        return data

    def _response_data(self):
        data = {
            'status_code': 200,
            'reason': 'OK',
            'headers': {
                'Content-Type': 'application/json',
                'Content-Length': 120
            },
        }

        return data


class ResponseTest(TestCase):

    def test_create_response(self):
        data = self._response_data()

        response = Response(uuid.uuid4(), data, Mock())

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.reason, 'OK')
        self.assertEqual(len(response.headers), 2)
        self.assertEqual(response.headers['Content-Type'], 'application/json')

    def test_response_repr(self):
        request_id = uuid.uuid4()
        data = self._response_data()

        response = Response(request_id, data, Mock())

        self.assertEqual(repr(response), "Response('{}', {})".format(request_id, data))

    def test_response_str(self):
        data = self._response_data()

        response = Response(uuid.uuid4(), data, Mock())

        self.assertEqual(str(response), '200 OK'.format(data))

    def test_load_response_body(self):
        mock_client = Mock()
        mock_client.response_body.return_value = b'the body'
        data = self._response_data()
        request_id = uuid.uuid4()

        response = Response(request_id, data, mock_client)
        body = response.body

        self.assertEqual(body, b'the body')
        mock_client.response_body.assert_called_once_with(request_id)

    def test_load_response_body_uses_cached_data(self):
        mock_client = Mock()
        mock_client.response_body.return_value = b'the body'
        data = self._response_data()
        request_id = uuid.uuid4()

        response = Response(request_id, data, mock_client)
        response.body  # Retrieves the body
        body = response.body  # Uses the previously retrieved body

        self.assertEqual(body, b'the body')
        mock_client.response_body.assert_called_once_with(request_id)

    def _response_data(self):
        data = {
            'status_code': 200,
            'reason': 'OK',
            'headers': {
                'Content-Type': 'application/json',
                'Content-Length': 120
            },
        }

        return data