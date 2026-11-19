#!/usr/bin/env python3
"""TLS-wrapped mock landing server for verifying TCP/TLS/cert/app probe statuses."""

import argparse
import socketserver
import ssl


def make_handler(landing_id: str, ssl_ctx: ssl.SSLContext):
    class TlsLandingHandler(socketserver.StreamRequestHandler):
        def setup(self) -> None:
            self.raw_peer = self.client_address
            self.request = ssl_ctx.wrap_socket(self.request, server_side=True)
            super().setup()

        def handle(self) -> None:
            peer_ip, peer_port = self.raw_peer[0], self.raw_peer[1]
            while True:
                line = self.rfile.readline()
                if not line:
                    break
                text = line.decode("utf-8", errors="replace").strip()
                reply = f"LANDING={landing_id} SRC={peer_ip} SPORT={peer_port} ECHO={text}\n"
                self.wfile.write(reply.encode("utf-8"))
                self.wfile.flush()

    return TlsLandingHandler


class ReuseThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--id", required=True)
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    args = parser.parse_args()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=args.cert, keyfile=args.key)
    srv = ReuseThreadingTCPServer((args.listen, args.port), make_handler(args.id, ctx))
    srv.serve_forever()


if __name__ == "__main__":
    main()
