import asyncio
import logging

from seleniumwire import storage
from seleniumwire.handler import InterceptRequestHandler
from seleniumwire.modifier import RequestModifier
# from seleniumwire.thirdparty.mitmproxy import addons
from seleniumwire.thirdparty.mitmproxy.master import Master
from seleniumwire.thirdparty.mitmproxy.options import Options
from seleniumwire.thirdparty.mitmproxy.server import ProxyConfig, ProxyServer
from seleniumwire.utils import build_proxy_args, extract_cert_and_key, get_upstream_proxy
from mitmproxy.master import Master
from mitmproxy.addons import (
    core, disable_h2c, proxyauth, proxyserver, dns_resolver, next_layer, save, tlsconfig,
    upstream_auth
)
from mitmproxy import optmanager

logger = logging.getLogger(__name__)

DEFAULT_VERIFY_SSL = False
DEFAULT_STREAM_WEBSOCKETS = True
DEFAULT_SUPPRESS_CONNECTION_ERRORS = True


class MitmProxy:
    """Run and manage a mitmproxy server instance."""

    def __init__(self, host, port, options):
        self.options = options

        # Used to stored captured requests
        self.storage = storage.create(**self._get_storage_args())
        extract_cert_and_key(self.storage.home_dir, cert_path=options.get('ca_cert'), key_path=options.get('ca_key'))

        # Used to modify requests/responses passing through the server
        # DEPRECATED. Will be superceded by request/response interceptors.
        self.modifier = RequestModifier()

        # The scope of requests we're interested in capturing.
        self.scopes = []

        self.request_interceptor = None
        self.response_interceptor = None

        self._event_loop = asyncio.new_event_loop()

        opts = Options()
        opts.update(
            confdir=self.storage.home_dir,
            listen_host=host,
            listen_port=port,
            ssl_insecure=not options.get('verify_ssl', DEFAULT_VERIFY_SSL),
            stream_websockets=DEFAULT_STREAM_WEBSOCKETS,
            suppress_connection_errors=options.get('suppress_connection_errors', DEFAULT_SUPPRESS_CONNECTION_ERRORS),
            **build_proxy_args(get_upstream_proxy(self.options)),
            # Options that are prefixed mitm_ are passed through to mitmproxy
            **{k[5:]: v for k, v in options.items() if k.startswith('mitm_')},
        )

        self.master = Master(opts, self._event_loop)
        self.master.addons.add(
            core.Core(),
            disable_h2c.DisableH2C(),
            proxyauth.ProxyAuth(),
            proxyserver.Proxyserver(),
            dns_resolver.DnsResolver(),
            next_layer.NextLayer(),
            save.Save(),
            tlsconfig.TlsConfig(),
            upstream_auth.UpstreamAuth(),
        )
        self.master.addons.add(SendToLogger())
        self.master.addons.add(InterceptRequestHandler(self))

        # self.master.server = ProxyServer(ProxyConfig(mitmproxy_opts))

        if options.get('disable_capture', False):
            self.scopes = ['$^']

    def serve_forever(self):
        """Run the server."""
        asyncio.set_event_loop(self._event_loop)
        self.master.run_loop(self._event_loop)

    def address(self):
        """Get a tuple of the address and port the proxy server
        is listening on.
        """
        # TODO: 修改
        return self.master.server.address

    def shutdown(self):
        """Shutdown the server and perform any cleanup."""
        self.master.shutdown()
        self.storage.cleanup()

    def _get_storage_args(self):
        storage_args = {
            'memory_only': self.options.get('request_storage') == 'memory',
            'base_dir': self.options.get('request_storage_base_dir'),
            'maxsize': self.options.get('request_storage_max_size'),
        }

        return storage_args


class SendToLogger:
    def log(self, entry):
        """Send a mitmproxy log message through our own logger."""
        getattr(logger, entry.level.replace('warn', 'warning'), logger.info)(entry.msg)
